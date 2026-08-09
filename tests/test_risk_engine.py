from models import Network
from risk_engine import calculate_risk


def test_open_network_is_high_risk():
    network = Network(
        ssid="TestOpen",
        signal=-50,
        security="Open"
    )

    score, level = calculate_risk(network)

    assert score == 80
    assert level == "High Risk"


def test_wpa_network_is_medium_risk():
    network = Network(
        ssid="TestWPA",
        signal=-60,
        security="WPA"
    )

    score, level = calculate_risk(network)

    assert score == 50
    assert level == "Medium Risk"


def test_wpa2_network_is_low_risk():
    network = Network(
        ssid="TestWPA2",
        signal=-60,
        security="WPA2"
    )

    score, level = calculate_risk(network)

    assert score == 25
    assert level == "Low Risk"


def test_wpa3_network_is_low_risk():
    network = Network(
        ssid="TestWPA3",
        signal=-60,
        security="WPA3"
    )

    score, level = calculate_risk(network)

    assert score == 10
    assert level == "Low Risk"


def test_unknown_network_has_medium_risk():
    network = Network(
        ssid="UnknownNetwork",
        signal=-60,
        security="Unknown"
    )

    score, level = calculate_risk(network)

    assert score == 60
    assert level == "Medium Risk"