package ma.enset.ebankingbackend;

import ma.enset.ebankingbackend.entities.AccountOperation;
import ma.enset.ebankingbackend.entities.CurrentAccount;
import ma.enset.ebankingbackend.entities.Customer;
import ma.enset.ebankingbackend.entities.SavingAccount;
import ma.enset.ebankingbackend.enums.AccountStatus;
import ma.enset.ebankingbackend.enums.OperationType;
import ma.enset.ebankingbackend.exceptions.BalanceNotSufficientException;
import ma.enset.ebankingbackend.exceptions.BankAccountNotFoundException;
import ma.enset.ebankingbackend.exceptions.CustomerNotFoundException;
import ma.enset.ebankingbackend.repositories.AccountOperationRepository;
import ma.enset.ebankingbackend.repositories.BankAccountRepository;
import ma.enset.ebankingbackend.repositories.CustomerRepository;
import ma.enset.ebankingbackend.services.BankAccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.Date;
import java.util.UUID;
import java.util.stream.Stream;

@SpringBootApplication
public class EBankingBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(EBankingBackendApplication.class, args);
    }

    @Bean
    CommandLineRunner start(
            BankAccountService bankAccountService
    ){
        return args -> {
            Stream.of("Akram","Tarik","Zakaria","Saad").forEach(
                    name->{
                        Customer customer = new Customer();
                        customer.setName(name);
                        customer.setEmail(name+"@gmail.com");
                        bankAccountService.saveCustomer(customer);
                    }
            );
            bankAccountService.listCustomers().forEach(
                    customer -> {
                        try {
                            bankAccountService.saveCurrentBankAccount(Math.random()*90000,9000, customer.getId());
                            bankAccountService.saveSavingBankAccount(Math.random()*120000,5.5, customer.getId());
                        } catch (CustomerNotFoundException e) {
                            e.printStackTrace();
                        }
                    }
            );
            bankAccountService.bankAccountList().forEach(
                    bankAccount -> {
                        for (int i =0; i<10; i++){
                            try {
                                bankAccountService.credit(bankAccount.getId(), 10000+Math.random()*120000,"Credit");
                                bankAccountService.debit(bankAccount.getId(), 1000+Math.random()*9000,"Debit");
                            } catch (BankAccountNotFoundException | BalanceNotSufficientException e) {
                                e.printStackTrace();
                            }
                        }
                    }
            );

        };
    }
}
