// Copyright 2026 QuickDesk Authors
#ifndef QUICKDESK_MANAGER_CLIPBOARDSYNC_H
#define QUICKDESK_MANAGER_CLIPBOARDSYNC_H

#include <QJsonObject>
#include <QObject>
#include <QTimer>
#include <memory>

namespace quickdesk {

class ClipboardSync : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)

public:
    explicit ClipboardSync(QObject* parent = nullptr);
    ~ClipboardSync() override;

    bool busy() const;
    void start(const QString& deviceId, const QString& connectionId, bool send);
    void cancelClient(const QString& connectionId = {});
    void cancelHost();

    static bool isClipboardMessage(const QJsonObject& message);
    void onRemoteMessage(const QString& connectionId, const QJsonObject& message);
    void onControllerMessage(const QJsonObject& message);

signals:
    void busyChanged();
    void finished(const QString& deviceId, const QString& message, bool success);
    void sendToRemote(const QString& connectionId, const QJsonObject& message);
    void sendToController(const QJsonObject& message);

private:
    struct Transfer;
    std::unique_ptr<Transfer> m_client;
    std::unique_ptr<Transfer> m_host;
    QTimer m_clientTimer;
    QTimer m_hostTimer;

    void handleRequest(const QJsonObject& message);
    void handleTransferMessage(Transfer& transfer, const QJsonObject& message);
    void sendMessage(const Transfer& transfer, const QString& operation, QJsonObject fields = {});
    void sendBatch(Transfer& transfer);
    void end(Transfer& transfer, const QString& status);
    void finishClient(const QString& deviceId, bool send, const QString& status);
};

} // namespace quickdesk

#endif
