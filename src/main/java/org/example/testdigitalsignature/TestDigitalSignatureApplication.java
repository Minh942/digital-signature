package org.example.testdigitalsignature;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class TestDigitalSignatureApplication {

    public static void main(String[] args) {
        SpringApplication.run(TestDigitalSignatureApplication.class, args);
    }

}
