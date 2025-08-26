package com.elearn.authentication.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collection = "refresh_tokens")
public class RefreshToken {
    @Id private String id;
    private String token;
    private String userId;
    private Instant expiryDate;
    private boolean revoked;
}
