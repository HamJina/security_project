package com.example.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "Customer")
@Getter @Setter
public class Customer {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String email;
    private String pwd;

    @Column(name = "role")
    private String role;
}
