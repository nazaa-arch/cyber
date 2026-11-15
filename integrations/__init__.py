"""Integrasi WAYANG dengan perangkat SOC satuan (Wazuh SIEM dan Suricata IDS/IPS).

* wazuh_export  : WAYANG -> Wazuh. Event bayangan ditulis sebagai JSON per baris
                  yang dibaca agen/manajer Wazuh (log_format json).
* suricata_eve  : Suricata -> WAYANG. Alert di eve.json menandai sumber; Kelir
                  memakai tanda itu untuk mengalihkan sumber tak terdaftar ke
                  bayangan dan memperingatkan Dalang bila sumbernya operator.
* engine.rulegen.suricata_rules : WAYANG -> Suricata. Draf rule per penyerang.
"""
