from pathlib import Path

from reconator.nmap import derive_web_urls, parse_nmap_xml_ports


def test_parse_nmap_xml_ports(tmp_path: Path) -> None:
    xml_content = """
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="Apache" version="2.4" />
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" tunnel="ssl" />
      </port>
    </ports>
  </host>
</nmaprun>
"""
    xml_path = tmp_path / "nmap.xml"
    xml_path.write_text(xml_content, encoding="utf-8")
    ports = parse_nmap_xml_ports(xml_path)
    assert 80 in ports
    assert ports[80]["name"] == "http"
    assert 443 in ports


def test_derive_web_urls() -> None:
    services = {
        80: {"name": "http", "tunnel": ""},
        443: {"name": "https", "tunnel": "ssl"},
        22: {"name": "ssh", "tunnel": ""},
    }
    urls = derive_web_urls("192.0.2.10", services)
    assert "http://192.0.2.10:80/" in urls
    assert "https://192.0.2.10:443/" in urls
