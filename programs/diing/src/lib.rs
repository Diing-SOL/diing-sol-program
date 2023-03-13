use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{CloseAccount, Mint, Token, TokenAccount, Transfer},
};

use hex;
use sha2::{Digest, Sha256};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod diing {
    use super::*;

    pub fn initialize_funds(
        ctx: Context<InitializeFunds>,
        bump: u8,
        ciphertext: String,
        amount: u64,
    ) -> Result<()> {
        let state = &mut ctx.accounts.application_state;
        state.ciphertext = ciphertext;
        state.user_sending = ctx.accounts.user_sending.key().clone();
        state.mint_of_token_being_sent = ctx.accounts.mint_of_token_being_sent.key().clone();
        state.escrow_wallet = ctx.accounts.escrow_wallet_state.key().clone();
        state.amount = amount;

        msg!("Initialized new Safe Transfer instance for {}", amount);

        let bump_vector = bump.to_le_bytes();
        let mint_of_token_being_sent_pk = ctx.accounts.mint_of_token_being_sent.key().clone();
        let inner = vec![
            b"state".as_ref(),
            ctx.accounts.user_sending.key.as_ref(),
            mint_of_token_being_sent_pk.as_ref(),
            bump_vector.as_ref(),
        ];
        let outer = vec![inner.as_slice()];

        // Below is the actual instruction that we are going to send to the Token program.
        let transfer_instruction = Transfer {
            from: ctx.accounts.wallet_to_withdraw_from.to_account_info(),
            to: ctx.accounts.escrow_wallet_state.to_account_info(),
            authority: ctx.accounts.user_sending.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            transfer_instruction,
            outer.as_slice(),
        );

        anchor_spl::token::transfer(cpi_ctx, state.amount)?;
        Ok(())
    }

    pub fn claim_funds(ctx: Context<ClaimFunds>, bump: u8, plaintext: String) -> Result<()> {
        // Verify the password
        let ciphertext = &ctx.accounts.application_state.ciphertext;
        let ciphertext = hex::decode(ciphertext).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(plaintext);
        let result = hasher.finalize();
        let result = result.as_slice();
        if result != ciphertext {
            return Err(ErrorCode::WrongPassword.into());
        }

        transfer_escrow_out(
            ctx.accounts.user_sending.to_account_info(),
            ctx.accounts.user_receiving.to_account_info(),
            ctx.accounts.mint_of_token_being_sent.to_account_info(),
            &mut ctx.accounts.escrow_wallet_state,
            ctx.accounts.application_state.to_account_info(),
            bump,
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.wallet_to_deposit_to.to_account_info(),
            ctx.accounts.application_state.amount,
        )?;
        Ok(())
    }
}
// ==================== State ====================

#[account]
#[derive(Default)]
pub struct State {
    ciphertext: String,
    user_sending: Pubkey,
    mint_of_token_being_sent: Pubkey,
    escrow_wallet: Pubkey,
    amount: u64,
}

// ==================== Instructions ====================

#[derive(Accounts)]
#[instruction(instance_bump: u8, bump: u8)]
pub struct Initialize<'info> {
    #[account(
        seeds=[b"instance".as_ref(), user.key.as_ref()],
        bump = instance_bump,
    )]
    /// CHECK: This is not dangerous
    instance: AccountInfo<'info>,
    #[account(
        init,
        payer = user,
        seeds=[b"wallet".as_ref(), user.key.as_ref(), mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = instance,
    )]
    wallet: Account<'info, TokenAccount>,
    #[account(mut)]
    mint: Account<'info, Mint>,
    #[account(mut)]
    user: Signer<'info>,
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct InitializeFunds<'info> {
    // Derived PDAs
    #[account(
        init,
        payer = user_sending,
        space = 8 + 8,
        seeds=[b"state".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref()],
        bump,
    )]
    application_state: Account<'info, State>,
    #[account(
        init,
        payer = user_sending,
        seeds=[b"wallet".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref()],
        bump,
        token::mint=mint_of_token_being_sent,
        token::authority=application_state,
    )]
    escrow_wallet_state: Account<'info, TokenAccount>,

    // Users and accounts in the system
    #[account(mut)]
    user_sending: Signer<'info>, // Alice
    mint_of_token_being_sent: Account<'info, Mint>, // USDC

    // Alice's USDC wallet that has already approved the escrow wallet
    #[account(
        mut,
        constraint=wallet_to_withdraw_from.owner == user_sending.key(),
        constraint=wallet_to_withdraw_from.mint == mint_of_token_being_sent.key()
    )]
    wallet_to_withdraw_from: Account<'info, TokenAccount>,

    // Application level accounts
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct ClaimFunds<'info> {
    #[account(
        mut,
        seeds=[b"state".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref()],
        bump = bump,
        has_one = user_sending,
        has_one = mint_of_token_being_sent,
    )]
    application_state: Account<'info, State>,
    #[account(
        mut,
        seeds=[b"wallet".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref()],
        bump = bump,
    )]
    escrow_wallet_state: Account<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = user_receiving,
        associated_token::mint = mint_of_token_being_sent,
        associated_token::authority = user_receiving,
    )]
    wallet_to_deposit_to: Account<'info, TokenAccount>, // Bob's USDC wallet (will be initialized if it did not exist)

    // Users and accounts in the system
    #[account(mut)]
    /// CHECK: This is not dangerous
    user_sending: AccountInfo<'info>, // Alice
    #[account(mut)]
    user_receiving: Signer<'info>, // Bob
    mint_of_token_being_sent: Account<'info, Mint>, // USDC

    // Application level accounts
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    associated_token_program: Program<'info, AssociatedToken>,
    rent: Sysvar<'info, Rent>,
}
// ==================== Utils ====================

fn transfer_escrow_out<'info>(
    user_sending: AccountInfo<'info>,
    user_receiving: AccountInfo<'info>,
    mint_of_token_being_sent: AccountInfo<'info>,
    escrow_wallet: &mut Account<'info, TokenAccount>,
    state: AccountInfo<'info>,
    state_bump: u8,
    token_program: AccountInfo<'info>,
    destination_wallet: AccountInfo<'info>,
    amount: u64,
) -> Result<()> {
    // Nothing interesting here! just boilerplate to compute our signer seeds for
    // signing on behalf of our PDA.
    let bump_vector = state_bump.to_le_bytes();
    let mint_of_token_being_sent_pk = mint_of_token_being_sent.key().clone();
    let inner = vec![
        b"state".as_ref(),
        user_sending.key.as_ref(),
        mint_of_token_being_sent_pk.as_ref(),
        bump_vector.as_ref(),
    ];
    let outer = vec![inner.as_slice()];

    // Perform the actual transfer
    let transfer_instruction = Transfer {
        from: escrow_wallet.to_account_info(),
        to: destination_wallet,
        authority: state.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        transfer_instruction,
        outer.as_slice(),
    );
    anchor_spl::token::transfer(cpi_ctx, amount)?;

    // Use the `reload()` function on an account to reload it's state. Since we performed the
    // transfer, we are expecting the `amount` field to have changed.
    let should_close = {
        escrow_wallet.reload()?;
        escrow_wallet.amount == 0
    };

    // If token account has no more tokens, it should be wiped out since it has no other use case.
    if should_close {
        let ca = CloseAccount {
            account: escrow_wallet.to_account_info(),
            destination: user_sending.to_account_info(),
            authority: state.to_account_info(),
        };
        let cpi_ctx =
            CpiContext::new_with_signer(token_program.to_account_info(), ca, outer.as_slice());
        anchor_spl::token::close_account(cpi_ctx)?;
    }

    Ok(())
}

// ==================== Errors ====================
#[error_code]
pub enum ErrorCode {
    #[msg("Wrong password!")]
    WrongPassword,
}
