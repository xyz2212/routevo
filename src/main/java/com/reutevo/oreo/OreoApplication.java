package com.reutevo.oreo;

import org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication(exclude = { PgVectorStoreAutoConfiguration.class })
@EnableScheduling
@EnableConfigurationProperties({ ApplicationProperties.class })
public class OreoApplication {

	public static void main(String[] args) {
		SpringApplication.run(OreoApplication.class, args);
	}

}
