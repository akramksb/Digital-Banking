package ma.enset.ebankingbackend.dtos;

import lombok.Data;
import ma.enset.ebankingbackend.enums.AccountStatus;

import java.util.Date;

@Data
public class SavingBankAccountDTO extends BankAccountDTO{
    private double interestRate;
}
