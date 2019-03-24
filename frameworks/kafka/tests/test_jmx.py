import pytest
import random
import string

import sdk_cmd
import sdk_tasks
import sdk_install
import sdk_security
import sdk_utils
import subprocess
from tests import config


def install_jmx_configured_kafka(self_signed_trust_store: bool = True):
    foldered_name = sdk_utils.get_foldered_name(config.SERVICE_NAME)
    sdk_install.uninstall(config.PACKAGE_NAME, foldered_name)
    test_run = random_string()
    create_keystore_cmd = ["keytool", "-genkey", "-alias", "self-signed-cert", "-keyalg",
                           "rsa", "-dname", "CN=myhost.example.com,O=Example Company,C=US",
                           "-keystore", "/tmp/{}-self-signed-keystore.ks".format(test_run), "-storepass", "deleteme",
                           "-keypass", "deleteme", "-storetype", "jks"]

    out = subprocess.check_output(create_keystore_cmd)
    print(out)

    create_keystore_cmd = ["keytool", "-list", "-v", "-keystore", "/tmp/{}-self-signed-keystore.ks".format(test_run),
                           "-storepass", "deleteme"]

    out = subprocess.check_output(create_keystore_cmd)
    print(out)

    write_to_file("deleteme", "/tmp/{}-keystorepass".format(test_run))
    write_to_file("admin adminpassword", "/tmp/{}-passwordfile".format(test_run))
    write_to_file("admin readwrite", "/tmp/{}-access".format(test_run))

    sdk_security.install_enterprise_cli(False)

    sdk_cmd.run_cli(
        "security secrets create -f /tmp/{}-self-signed-keystore.ks /test/integration/kafka/keystore".format(
            test_run))
    sdk_cmd.run_cli(
        "security secrets create -f /tmp/{}-passwordfile /test/integration/kafka/passwordfile".format(test_run))
    sdk_cmd.run_cli(
        "security secrets create -f /tmp/{}-keystorepass /test/integration/kafka/keypass".format(test_run))
    sdk_cmd.run_cli("security secrets create -f /tmp/{}-access /test/integration/kafka/access".format(test_run))

    service_options = {"service":
                       {"name": foldered_name, "jmx":
                        {"enabled": True, "port": 31199, "rmi_port": 31198,
                         "password_file": "/test/integration/kafka/passwordfile",
                         "access_file": "/test/integration/kafka/access",
                         "key_store": "/test/integration/kafka/keystore",
                         "key_store_password_file": "/test/integration/kafka/keypass"
                         }
                        }, "brokers": {"cpus": 0.5, "count": 1}}

    if self_signed_trust_store:
        service_options = sdk_utils.merge_dictionaries(
            {"service": {"jmx": {"add_trust_store": True,
                                 "trust_store": "/test/integration/kafka/keystore",
                                 "trust_store_password_file": "/test/integration/kafka/keypass"}}},
            service_options)
    if sdk_utils.is_strict_mode():
        kafka_sa = "test/integration/kafka/service-account"
        kafka_sa_secret = "test/integration/kafka/secret"

        sdk_security.setup_security(
            config.SERVICE_NAME,
            service_account=kafka_sa,
            service_account_secret=kafka_sa_secret,
        )
        service_options = sdk_utils.merge_dictionaries(
            {"service": {"service_account": kafka_sa, "service_account_secret": kafka_sa_secret}},
            service_options
        )

    sdk_install.install(
        package_name=config.PACKAGE_NAME,
        service_name=foldered_name,
        additional_options=service_options,
        expected_running_tasks=1
    )


def uninstall_jmx_secrets():
    sdk_security.delete_secret("/test/integration/kafka/keystore")
    sdk_security.delete_secret("/test/integration/kafka/passwordfile")
    sdk_security.delete_secret("/test/integration/kafka/access")
    sdk_security.delete_secret("/test/integration/kafka/keypass")


@pytest.mark.sanity
def test_secure_jmx_configuration():
    foldered_name = sdk_utils.get_foldered_name(config.SERVICE_NAME)

    try:
        install_jmx_configured_kafka()
        broker_task_id_0 = sdk_tasks.get_task_ids(foldered_name)[0]
        install_jmxterm(task_id=broker_task_id_0)
        generate_jmx_command_files(task_id=broker_task_id_0)

        cmd = "export JAVA_HOME=$(ls -d ${MESOS_SANDBOX}/jdk*/jre) && " \
              "${JAVA_HOME}/bin/java " \
              "-Duser.home=${MESOS_SANDBOX} " \
              "-Djdk.tls.client.protocols=TLSv1.2 -Djavax.net.ssl.trustStore=${MESOS_SANDBOX}/jmx/trust_store " \
              "-Djavax.net.ssl.trustStorePassword=deleteme " \
              "-Djavax.net.ssl.keyStore=${MESOS_SANDBOX}/jmx/key_store -Djavax.net.ssl.keyStorePassword=deleteme " \
              "-Djavax.net.ssl.trustStoreType=JKS -Djavax.net.ssl.keyStoreType=JKS -jar jmxterm-1.0.1-uber.jar " \
              "-l service:jmx:rmi:///jndi/rmi://${MESOS_CONTAINER_IP}:31199/jmxrmi -u admin -p adminpassword " \
              "-s -v silent -n < jmx_beans_command.txt"

        full_cmd = "bash -c '{}'".format(cmd)

        _, output, _ = sdk_cmd.run_cli("task exec {} {}".format(broker_task_id_0, full_cmd), print_output=True)

        assert "kafka.server:type=kafka-metrics-count" in output
        assert "kafka.server:name=BrokerState,type=KafkaServer" in output

        cmd = "export JAVA_HOME=$(ls -d ${MESOS_SANDBOX}/jdk*/jre) && " \
              "${JAVA_HOME}/bin/java " \
              "-Duser.home=${MESOS_SANDBOX} " \
              "-Djdk.tls.client.protocols=TLSv1.2 -Djavax.net.ssl.trustStore=${MESOS_SANDBOX}/jmx/trust_store " \
              "-Djavax.net.ssl.trustStorePassword=deleteme " \
              "-Djavax.net.ssl.keyStore=${MESOS_SANDBOX}/jmx/key_store -Djavax.net.ssl.keyStorePassword=deleteme " \
              "-Djavax.net.ssl.trustStoreType=JKS -Djavax.net.ssl.keyStoreType=JKS -jar jmxterm-1.0.1-uber.jar " \
              "-l service:jmx:rmi:///jndi/rmi://${MESOS_CONTAINER_IP}:31199/jmxrmi -u admin -p adminpassword " \
              "-s -v silent -n < jmx_domains_command.txt"

        full_cmd = "bash -c '{}'".format(cmd)

        rc, output, stderr = sdk_cmd.run_cli("task exec {} {}".format(broker_task_id_0, full_cmd), print_output=True)
        print(rc)
        print(output)
        print(stderr)

        assert "kafka.server" in output
        assert "kafka.controller" in output

    finally:
        sdk_install.uninstall(config.PACKAGE_NAME, foldered_name)
        uninstall_jmx_secrets()


@pytest.mark.sanity
def test_secure_jmx_dcos_crt():
    foldered_name = sdk_utils.get_foldered_name(config.SERVICE_NAME)

    try:
        install_jmx_configured_kafka(self_signed_trust_store=False)
        broker_task_id_0 = sdk_tasks.get_task_ids(foldered_name)[0]
        install_jmxterm(task_id=broker_task_id_0)
        generate_jmx_command_files(task_id=broker_task_id_0)

        cmd = "export JAVA_HOME=$(ls -d ${MESOS_SANDBOX}/jdk*/jre) && " \
              "${JAVA_HOME}/bin/java " \
              "-Duser.home=${MESOS_SANDBOX} " \
              "-Djdk.tls.client.protocols=TLSv1.2 -Djavax.net.ssl.trustStore=${JAVA_HOME}/lib/security/cacerts " \
              "-Djavax.net.ssl.trustStorePassword=changeit " \
              "-Djavax.net.ssl.keyStore=$MESOS_SANDBOX/jmx/key_store -Djavax.net.ssl.keyStorePassword=deleteme "  \
              "-Djavax.net.ssl.trustStoreType=JKS -Djavax.net.ssl.keyStoreType=JKS -jar jmxterm-1.0.1-uber.jar " \
              "-l service:jmx:rmi:///jndi/rmi://${MESOS_CONTAINER_IP}:31199/jmxrmi -u admin -p adminpassword " \
              "-s -v silent -n < jmx_beans_command.txt"

        full_cmd = "bash -c '{}'".format(cmd)

        _, output, _ = sdk_cmd.run_cli("task exec {} {}".format(broker_task_id_0, full_cmd), print_output=True)

        assert "kafka.server:type=kafka-metrics-count" in output
        assert "kafka.server:name=BrokerState,type=KafkaServer" in output

    finally:
        sdk_install.uninstall(config.PACKAGE_NAME, foldered_name)
        uninstall_jmx_secrets()


def random_string(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def write_to_file(content, file_path):
    text_file = open(file_path, "w+")
    text_file.write(content)
    text_file.close()


def generate_jmx_command_files(task_id: string):
    cmd = "\n".join(
        [
            "echo beans >> jmx_beans_command.txt && ",
            "echo domains >> jmx_domains_command.txt",
        ]
    )
    full_cmd = "bash -c '{}'".format(cmd)
    rc, _, _ = sdk_cmd.run_cli("task exec {} {}".format(task_id, full_cmd), print_output=True)
    assert rc == 0, "Error creating jmx_commands file"


def install_jmxterm(task_id: string):
    jmx_term_url = 'https://github.com/jiaqi/jmxterm/releases/download/v1.0.1/jmxterm-1.0.1-uber.jar'
    cmd = "wget {}".format(jmx_term_url)
    full_cmd = "bash -c '{}'".format(cmd)
    rc, _, _ = sdk_cmd.run_cli("task exec {} {}".format(task_id, full_cmd), print_output=True)
    assert rc == 0, "Error downloading jmxterm {}".format(jmx_term_url)
