package com.demo.upimesh.demo;

import com.demo.upimesh.domain.Account;
import com.demo.upimesh.domain.AccountRepository;
import com.demo.upimesh.domain.Payment;
import com.demo.upimesh.domain.PaymentRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

/**
 * Demo-only endpoints behind the simulator page. Active only with the {@code demo}
 * profile — never part of the production surface.
 */
@RestController
@RequestMapping("/api")
@Profile("demo")
public class DemoController {

    private final SimService sim;
    private final AccountRepository accounts;
    private final PaymentRepository payments;

    public DemoController(SimService sim, AccountRepository accounts, PaymentRepository payments) {
        this.sim = sim;
        this.accounts = accounts;
        this.payments = payments;
    }

    public record PayRequest(@NotBlank String from, @NotBlank String to, @NotNull BigDecimal amount) {}

    @GetMapping("/sim/state")
    public Map<String, Object> state() { return sim.state(); }

    @PostMapping("/sim/step")
    public Map<String, Object> step(@RequestParam(defaultValue = "1") int n) {
        sim.step(n);
        return sim.state();
    }

    @PostMapping("/sim/pay")
    public SimService.PaymentView pay(@Valid @RequestBody PayRequest r) {
        return sim.pay(r.from(), r.to(), r.amount());
    }

    @PostMapping("/sim/nodes/{nodeId}/walk-to-coverage")
    public Map<String, Object> walk(@PathVariable String nodeId) {
        sim.walkToCoverage(nodeId);
        return Map.of("status", "walking");
    }

    @PostMapping("/sim/attack/{kind}")
    public List<SimService.PaymentView> attack(@PathVariable String kind) { return sim.attack(kind); }

    @PostMapping("/sim/reset")
    public Map<String, Object> reset() {
        sim.reset();
        return sim.state();
    }

    @GetMapping("/accounts")
    public List<Account> accounts() { return accounts.findAll(); }

    @GetMapping("/transactions")
    public List<Payment> transactions() { return payments.findTop20ByOrderByIdDesc(); }
}
