// Copyright 2026 QuickDesk Authors
#include "ClipboardSync.h"

#include <monocypher.h>

#include <QBuffer>
#include <QClipboard>
#include <QGuiApplication>
#include <QImageReader>
#include <QMimeData>
#include <QRandomGenerator>
#include <QUuid>
#include <QUrl>
#include <algorithm>
#include <array>
#include <cstring>

namespace quickdesk {
namespace {

const auto kMessageType = QStringLiteral("quickdesk.clipboard.v1");
constexpr qsizetype kMaxClipboardBytes = 16 * 1024 * 1024;
constexpr qint64 kMaxImagePixels = 32 * 1024 * 1024;
constexpr qsizetype kChunkSize = 24 * 1024;
constexpr qsizetype kBatchSize = 8 * kChunkSize;
constexpr qsizetype kNonceSize = 24;
constexpr qsizetype kTagSize = 16;
constexpr qsizetype kEnvelopeSize = kNonceSize + kTagSize;
constexpr qsizetype kMaxPacketSize = kMaxClipboardBytes + 1 + kEnvelopeSize;
using Key = std::array<uint8_t, 32>;

uint8_t* bytes(char* data) { return reinterpret_cast<uint8_t*>(data); }
const uint8_t* bytes(const char* data) { return reinterpret_cast<const uint8_t*>(data); }

template <size_t Size>
void randomize(uint8_t* output)
{
    static_assert(Size % sizeof(quint32) == 0);
    std::array<quint32, Size / sizeof(quint32)> words;
    QRandomGenerator::system()->fillRange(words.data(), words.size());
    std::memcpy(output, words.data(), Size);
    crypto_wipe(words.data(), Size);
}

bool supportedSize(const QSize& size)
{
    return size.isValid() && !size.isEmpty()
        && qint64(size.width()) * size.height() <= kMaxImagePixels;
}

// A leading byte holds the format inside the authenticated payload.
QString readClipboard(QByteArray& payload)
{
    const auto* clipboard = QGuiApplication::clipboard();
    const QMimeData* mime = clipboard ? clipboard->mimeData() : nullptr;
    if (!mime || mime->formats().isEmpty()) {
        return QStringLiteral("empty");
    }
    if (mime->hasImage()) {
        const QImage image = qvariant_cast<QImage>(mime->imageData());
        if (image.isNull()) {
            return QStringLiteral("readFailed");
        }
        if (!supportedSize(image.size())) {
            return QStringLiteral("tooLarge");
        }
        QBuffer output(&payload);
        output.open(QIODevice::WriteOnly);
        output.putChar('P');
        if (!image.save(&output, "PNG")) {
            return QStringLiteral("readFailed");
        }
    } else {
        const auto urls = mime->urls();
        if (std::any_of(urls.cbegin(), urls.cend(), [](const QUrl& url) { return url.isLocalFile(); })) {
            return QStringLiteral("files");
        }
        if (!mime->hasText()) {
            return QStringLiteral("unsupported");
        }
        const QString text = mime->text();
        if (text.isEmpty()) {
            return QStringLiteral("empty");
        }
        if (text.size() > kMaxClipboardBytes) {
            return QStringLiteral("tooLarge");
        }
        payload = QByteArray(1, 'T') + text.toUtf8();
    }

    return payload.size() > kMaxClipboardBytes + 1
        ? QStringLiteral("tooLarge") : QStringLiteral("ok");
}

QString writeClipboard(const QByteArray& payload)
{
    auto* clipboard = QGuiApplication::clipboard();
    if (!clipboard) {
        return QStringLiteral("writeFailed");
    }
    if (payload.size() < 2) {
        return QStringLiteral("invalid");
    }
    if (payload.front() == 'T') {
        const QString text = QString::fromUtf8(payload.constData() + 1, payload.size() - 1);
        if (text.toUtf8() != QByteArrayView(payload).sliced(1)) {
            return QStringLiteral("invalid");
        }
        clipboard->setText(text);
        const QString current = clipboard->text();
#ifdef Q_OS_WIN
        // Windows can normalize clipboard line endings on the round trip.
        if (QString(text).replace(QStringLiteral("\r\n"), QStringLiteral("\n"))
            == QString(current).replace(QStringLiteral("\r\n"), QStringLiteral("\n"))) {
            return QStringLiteral("ok");
        }
#endif
        return current == text ? QStringLiteral("ok") : QStringLiteral("writeFailed");
    }
    if (payload.front() != 'P') {
        return QStringLiteral("invalid");
    }

    QBuffer input;
    input.setData(QByteArray::fromRawData(payload.constData() + 1, payload.size() - 1));
    input.open(QIODevice::ReadOnly);
    QImageReader reader(&input, "png");
    if (!supportedSize(reader.size())) {
        return QStringLiteral("invalid");
    }
    const QImage image = reader.read();
    if (image.isNull()) {
        return QStringLiteral("invalid");
    }
    clipboard->setImage(image);
    const QImage current = clipboard->image();
    return current == image ? QStringLiteral("ok") : QStringLiteral("writeFailed");
}

QByteArray decodeBase64(const QJsonValue& field, qsizetype maxBytes)
{
    const QString value = field.toString();
    if (value.size() > (maxBytes + 2) / 3 * 4) {
        return {};
    }
    const auto result = QByteArray::fromBase64Encoding(value.toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
    return result && result.decoded.size() <= maxBytes ? result.decoded : QByteArray{};
}

} // namespace

struct ClipboardSync::Transfer {
    QByteArray makePublicKey()
    {
        randomize<32>(key.data());
        crypto_x25519_public_key(publicKey.data(), key.data());
        return QByteArray(reinterpret_cast<const char*>(publicKey.data()), publicKey.size()).toBase64();
    }

    bool agreeKey(const QJsonValue& field)
    {
        const auto peerKey = decodeBase64(field, 32);
        if (peerKey.size() != 32) {
            return false;
        }
        // The host bridge can send to a different client when several are connected.
        // Bind the key to the controller and host public keys in that order.
        std::array<uint8_t, 96> material;
        crypto_x25519(material.data(), key.data(), bytes(peerKey.constData()));
        const Key zero{};
        const bool valid = crypto_verify32(material.data(), zero.data()) != 0;
        if (valid) {
            const auto* controllerKey = isClient ? publicKey.data() : bytes(peerKey.constData());
            const auto* hostKey = isClient ? bytes(peerKey.constData()) : publicKey.data();
            std::copy_n(controllerKey, 32, material.begin() + 32);
            std::copy_n(hostKey, 32, material.begin() + 64);
            crypto_blake2b(key.data(), key.size(), material.data(), material.size());
        }
        crypto_wipe(material.data(), material.size());
        return valid;
    }

    void seal()
    {
        QByteArray packet(data.size() + kEnvelopeSize, Qt::Uninitialized);
        auto* nonce = bytes(packet.data());
        randomize<kNonceSize>(nonce);
        const auto requestId = id.toUtf8();
        crypto_aead_lock(nonce + kEnvelopeSize, nonce + kNonceSize, key.data(), nonce,
                         bytes(requestId.constData()), requestId.size(),
                         bytes(data.constData()), data.size());
        data = std::move(packet);
    }

    QString open()
    {
        if (data.size() <= kEnvelopeSize) {
            return QStringLiteral("invalid");
        }
        const auto* nonce = bytes(data.constData());
        QByteArray payload(data.size() - kEnvelopeSize, Qt::Uninitialized);
        const auto requestId = id.toUtf8();
        if (crypto_aead_unlock(bytes(payload.data()), nonce + kNonceSize, key.data(), nonce,
                               bytes(requestId.constData()), requestId.size(),
                               nonce + kEnvelopeSize, payload.size()) != 0) {
            return QStringLiteral("invalid");
        }
        return writeClipboard(payload);
    }

    ~Transfer() { crypto_wipe(key.data(), key.size()); }

    QString deviceId;
    QString connectionId;
    QString id;
    QByteArray data;
    Key key{};
    Key publicKey{};
    qsizetype offset = 0;
    bool isClient = false;
    bool sending = false;
    bool ready = false;
};

ClipboardSync::ClipboardSync(QObject* parent)
    : QObject(parent)
{
    m_clientTimer.setSingleShot(true);
    m_clientTimer.setInterval(15000);
    m_hostTimer.setSingleShot(true);
    m_hostTimer.setInterval(15000);
    connect(&m_clientTimer, &QTimer::timeout, this, [this] {
        end(*m_client, m_client->ready ? QStringLiteral("timeout") : QStringLiteral("noResponse"));
    });
    connect(&m_hostTimer, &QTimer::timeout, this, &ClipboardSync::cancelHost);
}

ClipboardSync::~ClipboardSync() = default;

bool ClipboardSync::busy() const
{
    return bool(m_client);
}

bool ClipboardSync::isClipboardMessage(const QJsonObject& message)
{
    return message.value("type").toString() == kMessageType;
}

void ClipboardSync::start(const QString& deviceId, const QString& connectionId, bool send)
{
    if (busy()) {
        finishClient(deviceId, send, QStringLiteral("busy"));
        return;
    }
    if (connectionId.isEmpty()) {
        finishClient(deviceId, send, QStringLiteral("disconnected"));
        return;
    }
    auto transfer = std::make_unique<Transfer>();
    transfer->deviceId = deviceId;
    transfer->connectionId = connectionId;
    transfer->id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    transfer->isClient = true;
    transfer->sending = send;

    if (send) {
        const QString status = readClipboard(transfer->data);
        if (status != QStringLiteral("ok")) {
            finishClient(deviceId, send, status);
            return;
        }
    }

    const auto publicKey = transfer->makePublicKey();
    m_client = std::move(transfer);
    m_clientTimer.start();
    emit busyChanged();
    sendMessage(*m_client, QStringLiteral("request"), {
        { "push", send },
        { "publicKey", QString::fromLatin1(publicKey) }
    });
}

void ClipboardSync::cancelClient(const QString& connectionId)
{
    if (m_client && (connectionId.isEmpty() || m_client->connectionId == connectionId)) {
        end(*m_client, QStringLiteral("disconnected"));
    }
}

void ClipboardSync::cancelHost()
{
    m_hostTimer.stop();
    m_host.reset();
}

void ClipboardSync::onRemoteMessage(const QString& connectionId, const QJsonObject& message)
{
    if (m_client && m_client->connectionId == connectionId && m_client->id == message.value("id").toString()) {
        handleTransferMessage(*m_client, message);
    }
}

void ClipboardSync::onControllerMessage(const QJsonObject& message)
{
    if (message.value("op").toString() == QStringLiteral("request")) {
        handleRequest(message);
    } else if (m_host && m_host->id == message.value("id").toString()) {
        handleTransferMessage(*m_host, message);
    }
}

void ClipboardSync::handleRequest(const QJsonObject& message)
{
    const QString id = message.value("id").toString();
    if (id.size() != 36 || QUuid::fromString(id).isNull() || !message.value("push").isBool()) {
        return;
    }
    auto transfer = std::make_unique<Transfer>();
    transfer->id = id;
    transfer->sending = !message.value("push").toBool();
    if (m_host) {
        if (id != m_host->id) {
            end(*transfer, QStringLiteral("busy"));
        }
        return;
    }

    const auto publicKey = transfer->makePublicKey();
    if (!transfer->agreeKey(message.value("publicKey"))) {
        end(*transfer, QStringLiteral("invalid"));
        return;
    }
    if (transfer->sending) {
        const QString status = readClipboard(transfer->data);
        if (status != QStringLiteral("ok")) {
            end(*transfer, status);
            return;
        }
        transfer->seal();
    }
    transfer->ready = true;
    m_host = std::move(transfer);
    m_hostTimer.start();
    sendMessage(*m_host, QStringLiteral("ready"), {
        { "publicKey", QString::fromLatin1(publicKey) }
    });
}

void ClipboardSync::handleTransferMessage(Transfer& transfer, const QJsonObject& message)
{
    const auto op = message.value("op").toString();
    if (op == QStringLiteral("done")) {
        const auto status = message.value("status").toString();
        const bool complete = transfer.sending && transfer.ready && transfer.offset == transfer.data.size();
        if (transfer.isClient) {
            end(transfer, status == QStringLiteral("ok") && !complete ? QStringLiteral("invalid") : status);
        } else {
            cancelHost();
        }
        return;
    }

    auto& timer = transfer.isClient ? m_clientTimer : m_hostTimer;
    if (!transfer.ready) {
        if (op != QStringLiteral("ready") || !transfer.agreeKey(message.value("publicKey"))) {
            end(transfer, QStringLiteral("invalid"));
            return;
        }
        transfer.ready = true;
        timer.start();
        if (transfer.sending) {
            transfer.seal();
            sendBatch(transfer);
        } else {
            sendMessage(transfer, QStringLiteral("next"), {{ "offset", 0 }});
        }
        return;
    }

    const int offset = message.value("offset").toInt(-1);
    if (transfer.sending) {
        if (op != QStringLiteral("next") || offset != transfer.offset || offset >= transfer.data.size()) {
            end(transfer, QStringLiteral("invalid"));
            return;
        }
        timer.start();
        sendBatch(transfer);
        return;
    }

    const auto last = message.value("last");
    const auto chunk = decodeBase64(message.value("data"), kChunkSize);
    if (op != QStringLiteral("data") || offset != transfer.data.size() || !last.isBool()
        || chunk.isEmpty() || (!last.toBool() && chunk.size() != kChunkSize)
        || transfer.data.size() + chunk.size() > kMaxPacketSize) {
        end(transfer, QStringLiteral("invalid"));
        return;
    }
    transfer.data.append(chunk);
    if (last.toBool()) {
        end(transfer, transfer.open());
    } else {
        timer.start();
        if (transfer.data.size() % kBatchSize == 0) {
            sendMessage(transfer, QStringLiteral("next"), {{ "offset", int(transfer.data.size()) }});
        }
    }
}

void ClipboardSync::sendBatch(Transfer& transfer)
{
    const qsizetype endOffset = std::min(transfer.data.size(), transfer.offset + kBatchSize);
    while (transfer.offset < endOffset) {
        const auto offset = transfer.offset;
        const auto chunk = transfer.data.mid(offset, kChunkSize);
        transfer.offset += chunk.size();
        sendMessage(transfer, QStringLiteral("data"), {
            { "offset", int(offset) },
            { "last", transfer.offset == transfer.data.size() },
            { "data", QString::fromLatin1(chunk.toBase64()) }
        });
    }
}

void ClipboardSync::sendMessage(const Transfer& transfer, const QString& operation, QJsonObject fields)
{
    fields["type"] = kMessageType;
    fields["id"] = transfer.id;
    fields["op"] = operation;
    if (transfer.isClient) {
        emit sendToRemote(transfer.connectionId, fields);
    } else {
        emit sendToController(fields);
    }
}

void ClipboardSync::end(Transfer& transfer, const QString& status)
{
    if (transfer.isClient) {
        const QString deviceId = transfer.deviceId;
        const bool sent = transfer.sending;
        if (transfer.ready && !sent) {
            sendMessage(transfer, QStringLiteral("done"), {{ "status", status }});
        }
        m_clientTimer.stop();
        m_client.reset();
        emit busyChanged();
        finishClient(deviceId, sent, status);
    } else {
        sendMessage(transfer, QStringLiteral("done"), {{ "status", status }});
        if (m_host.get() == &transfer) {
            cancelHost();
        }
    }
}

void ClipboardSync::finishClient(const QString& deviceId, bool send, const QString& status)
{
    const bool success = status == QStringLiteral("ok");
    QString message;
    if (success) {
        message = send ? tr("Clipboard sent to the remote device.")
                       : tr("Remote clipboard copied to this device.");
    } else if (status == QStringLiteral("empty")) {
        message = send ? tr("The local clipboard is empty.") : tr("The remote clipboard is empty.");
    } else if (status == QStringLiteral("files")) {
        message = tr("Use file transfer for files copied from a file manager.");
    } else if (status == QStringLiteral("tooLarge")) {
        message = tr("Clipboard content is too large (16 MiB or 32 megapixels max).");
    } else if (status == QStringLiteral("unsupported")) {
        message = tr("The clipboard contains no supported text or image.");
    } else if (status == QStringLiteral("readFailed")) {
        message = tr("Could not read the source clipboard.");
    } else if (status == QStringLiteral("writeFailed")) {
        message = tr("Could not write to the destination clipboard.");
    } else if (status == QStringLiteral("busy")) {
        message = tr("A clipboard sync is already in progress.");
    } else if (status == QStringLiteral("disconnected")) {
        message = tr("Clipboard sync requires an active connection.");
    } else if (status == QStringLiteral("noResponse")) {
        message = tr("Clipboard sync received no response. Check that both QuickDesk apps are updated.");
    } else if (status == QStringLiteral("timeout")) {
        message = tr("Clipboard sync timed out. Please try again.");
    } else {
        message = tr("Clipboard sync failed. Please try again.");
    }
    emit finished(deviceId, message, success);
}

} // namespace quickdesk
