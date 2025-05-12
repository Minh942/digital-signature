package org.example.testdigitalsignature.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SigningWebController {
    /**
     * Hiển thị trang ký số
     */
    @GetMapping("/sign")
    public String showSigningPage(Model model) {
        model.addAttribute("title", "Ký số tài liệu PDF");
        return "signing";
    }

    @GetMapping
    public String home(Model model) {
        model.addAttribute("message", "Chào mừng đến với ứng dụng ký số PDF");
        return "home";
    }

}
