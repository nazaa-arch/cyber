FROM wazuh/wazuh-manager:4.14.9
COPY wazuh/wayang_rules.xml /var/ossec/etc/rules/wayang_rules.xml
COPY wazuh/ossec_localfile.xml /tmp/wayang_localfile.xml
RUN cat /tmp/wayang_localfile.xml >> /var/ossec/etc/ossec.conf \
 && chown wazuh:wazuh /var/ossec/etc/rules/wayang_rules.xml
