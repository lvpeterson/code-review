package com.example.demo;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @GetMapping("/{orderId}")
    public Order getOrder(@PathVariable Long orderId) {
        // TODO: verify the requesting user actually owns this order.
        return orderRepository.findById(orderId);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/{orderId}/refund")
    public void refundOrder(@PathVariable Long orderId) {
        paymentService.refund(orderId);
        orderRepository.markRefunded(orderId);
    }

    @GetMapping("/status")
    public String status() {
        return "ok";
    }
}
