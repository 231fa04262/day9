package com.vignan.jwtdemo.service;

import com.vignan.jwtdemo.model.LogEntry;
import com.vignan.jwtdemo.repository.LogEntryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class LoggingService {

    private static final Logger logger = LoggerFactory.getLogger(LoggingService.class);

    private final LogEntryRepository logEntryRepository;

    public LoggingService(LogEntryRepository logEntryRepository) {
        this.logEntryRepository = logEntryRepository;
    }

    public void logAction(String username, String action, String request, String response) {
        logger.info("User: {}, Action: {}, Request: {}, Response: {}", username, action, request, response);

        LogEntry logEntry = new LogEntry();
        logEntry.setUsername(username);
        logEntry.setAction(action);
        logEntry.setRequest(request);
        logEntry.setResponse(response);
        logEntry.setTimestamp(LocalDateTime.now());

        logEntryRepository.save(logEntry);
    }
}
