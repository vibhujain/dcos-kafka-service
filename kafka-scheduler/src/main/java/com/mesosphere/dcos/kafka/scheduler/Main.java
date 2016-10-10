package com.mesosphere.dcos.kafka.scheduler;

import com.mesosphere.dcos.kafka.cmd.CmdExecutor;
import com.mesosphere.dcos.kafka.config.DropwizardConfiguration;
import com.mesosphere.dcos.kafka.config.KafkaSchedulerConfiguration;
import com.mesosphere.dcos.kafka.state.ClusterState;
import com.mesosphere.dcos.kafka.web.*;
import io.dropwizard.Application;
import io.dropwizard.configuration.EnvironmentVariableLookup;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.java8.Java8Bundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.apache.mesos.config.api.ConfigResource;
import org.apache.mesos.dcos.DcosCluster;
import org.apache.mesos.scheduler.plan.api.PlanResource;
import org.apache.mesos.scheduler.recovery.api.RecoveryResource;
import org.apache.mesos.state.api.JsonPropertyDeserializer;
import org.apache.mesos.state.api.StateResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URISyntaxException;
import java.util.concurrent.ExecutorService;

/**
 * Main entry point for the Scheduler.
 */
public final class Main extends Application<DropwizardConfiguration> {
  private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);
  private DropwizardConfiguration dropwizardConfiguration;
  private Environment environment;

  public static void main(String[] args) throws Exception {
    new Main().run(args);
  }

  public Main() {
    super();
  }

  ExecutorService kafkaSchedulerExecutorService = null;

  @Override
  public String getName() {
    return "DCOS Kafka Service";
  }

  @Override
  public void initialize(Bootstrap<DropwizardConfiguration> bootstrap) {
    super.initialize(bootstrap);

    StrSubstitutor strSubstitutor = new StrSubstitutor(new EnvironmentVariableLookup(false));
    strSubstitutor.setEnableSubstitutionInVariables(true);

    bootstrap.addBundle(new Java8Bundle());
    bootstrap.setConfigurationSourceProvider(
            new SubstitutingSourceProvider(
                    bootstrap.getConfigurationSourceProvider(),
                    strSubstitutor));
  }

  public DropwizardConfiguration getDropwizardConfiguration() {
    return dropwizardConfiguration;
  }

  Environment getEnvironment() {
    return environment;
  }

  @Override
  public void run(DropwizardConfiguration dropwizardConfiguration, Environment environment) throws Exception {
    LOGGER.info("DropwizardConfiguration: " + dropwizardConfiguration);
    this.dropwizardConfiguration = dropwizardConfiguration;
    this.environment = environment;

    final KafkaScheduler kafkaScheduler =
            new KafkaScheduler(dropwizardConfiguration.getSchedulerConfiguration(), getEnvironment());

    registerJerseyResources(kafkaScheduler, getEnvironment(), this.dropwizardConfiguration);
    registerHealthChecks(kafkaScheduler, getEnvironment());

    kafkaSchedulerExecutorService = environment.lifecycle().
            executorService("KafkaScheduler")
            .minThreads(1)
            .maxThreads(2)
            .build();
    kafkaSchedulerExecutorService.submit(kafkaScheduler);
  }

  private void registerJerseyResources(
          KafkaScheduler kafkaScheduler,
          Environment environment,
          DropwizardConfiguration configuration) throws URISyntaxException {
    // Kafka-specific APIs:
    environment.jersey().register(new ConnectionController(
            configuration.getSchedulerConfiguration().getFullKafkaZookeeperPath(),
            kafkaScheduler.getConfigState(),
            kafkaScheduler.getKafkaState(),
            new ClusterState(new DcosCluster()),
            configuration.getSchedulerConfiguration().getZookeeperConfig().getFrameworkName()));
    environment.jersey().register(new BrokerController(kafkaScheduler));
    environment.jersey().register(new TopicController(
            new CmdExecutor(configuration.getSchedulerConfiguration(), kafkaScheduler),
            kafkaScheduler));
    environment.jersey().register(new RecoveryResource(kafkaScheduler.getRecoveryStatusRef()));

    // APIs from dcos-commons:
    environment.jersey().register(new ConfigResource<>(
            kafkaScheduler.getConfigState().getConfigStore(), KafkaSchedulerConfiguration.getFactoryInstance()));
    environment.jersey().register(new StateResource(
            kafkaScheduler.getFrameworkState().getStateStore(),
            new JsonPropertyDeserializer(),
            configuration.getSchedulerConfiguration().getServiceConfiguration().getName()));
    environment.jersey().register(new PlanResource(kafkaScheduler.getPlanManager()));
  }

  private void registerHealthChecks(
          KafkaScheduler kafkaScheduler,
          Environment environment) {

    environment.healthChecks().register(
        BrokerCheck.NAME,
        new BrokerCheck(kafkaScheduler));
    environment.healthChecks().register(
            RegisterCheck.NAME,
            new RegisterCheck(kafkaScheduler));
  }
}
