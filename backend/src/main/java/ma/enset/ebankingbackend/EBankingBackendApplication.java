package ma.enset.ebankingbackend;

import ma.enset.ebankingbackend.dtos.BankAccountDTO;
import ma.enset.ebankingbackend.dtos.CurrentBankAccountDTO;
import ma.enset.ebankingbackend.dtos.CustomerDTO;
import ma.enset.ebankingbackend.dtos.SavingBankAccountDTO;
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
import ma.enset.ebankingbackend.security.entities.AppRole;
import ma.enset.ebankingbackend.security.entities.AppUser;
import ma.enset.ebankingbackend.security.service.AccountService;
import ma.enset.ebankingbackend.services.BankAccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

@SpringBootApplication
public class EBankingBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(EBankingBackendApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner start(
            BankAccountService bankAccountService,
            AccountService accountService
    ){
        return args -> {
            // ***************************************
            accountService.addNewRole(new AppRole(null, "USER"));
            accountService.addNewRole(new AppRole(null, "ADMIN"));

            accountService.addNewUser(new AppUser(null, "akram", "1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null, "tarik","1234",new ArrayList<>()));

            accountService.addRoleToUser("tarik", "USER");
            accountService.addRoleToUser("akram", "ADMIN");
            accountService.addRoleToUser("akram", "USER");
            // ***************************************
            Stream.of("Akram","Tarik","Zakaria","Saad").forEach(
                    name->{
                        CustomerDTO customerDTO = new CustomerDTO();
                        customerDTO.setName(name);
                        customerDTO.setEmail(name+"@gmail.com");
                        bankAccountService.saveCustomer(customerDTO);
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
