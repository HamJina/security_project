package com.example.controller;

import com.example.model.Customer;
import com.example.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController{

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder; //비밀번호 암호화해서 저장

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        try {
            String hashPwd = passwordEncoder.encode(customer.getPwd());
            customer.setPwd(hashPwd);
            Customer savedCustomer = customerRepository.save(customer);

            //객체저장 성공시
            if(savedCustomer.getId()>0) {
                return ResponseEntity.status(HttpStatus.CREATED)
                        .body("주어진 사용자 정보가 성공적으로 등록되었습니다.");
            }else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("사용자 등록에 실패했습니다.");
            }
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("예외가 발생했습니다: " + ex.getMessage()); //500코드 반환
        }
    }
}
