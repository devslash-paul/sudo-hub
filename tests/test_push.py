from pathlib import Path

from sudo_hub.server import Broker


def test_vapid_key_is_persisted_and_public_key_is_uncompressed(tmp_path: Path):
    broker = Broker(tmp_path, "https://approve.test", "approve.test", "client-token", "enroll-token")
    first = broker.vapid_public_key()
    assert len(first) == 87
    assert Broker(tmp_path, "https://approve.test", "approve.test", "client-token", "enroll-token").vapid_public_key() == first


def test_push_subscription_is_deduplicated(tmp_path: Path):
    broker = Broker(tmp_path, "https://approve.test", "approve.test", "client-token", "enroll-token")
    subscription = {"endpoint":"https://push.test/one", "keys":{"p256dh":"key", "auth":"auth"}}
    broker.add_push_subscription(subscription)
    broker.add_push_subscription(subscription)
    assert broker.push_subscriptions == [subscription]
