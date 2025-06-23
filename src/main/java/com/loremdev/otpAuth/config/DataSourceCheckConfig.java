package com.loremdev.otpAuth.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.sql.Connection;

@Configuration
public class DataSourceCheckConfig {
    @Bean
    public CommandLineRunner validateDataSource(DataSource dataSource) {
        return args ->{
            try(Connection conn = dataSource.getConnection()){
                System.out.println("✅ Successfully connected to: "+ conn.getMetaData().getURL());
            }catch(Exception e){
                System.err.println("❌ Failed to connect to database:");
                e.printStackTrace();
                System.exit(1);
            }
        };
    }
}
