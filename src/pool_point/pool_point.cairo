use starknet::{ContractAddress, get_tx_info};
use core::pedersen::PedersenTrait;
use core::hash::{HashStateTrait, HashStateExTrait};
use starknet::get_caller_address;


#[starknet::interface]
trait IPoolPoint<TContractState> {
    fn rewardPoint(ref self: TContractState, amount: u128, timestamp: u128, proof: Array<felt252>);
    fn givePoint(ref self: TContractState, addressReceive: ContractAddress, amount: u128);
    fn setPermission(ref self: TContractState, address: ContractAddress, permission: bool);
    fn get(self: @TContractState, address: ContractAddress) -> u128;
    fn getOwner(self: @TContractState) -> ContractAddress;
}


#[starknet::contract]
mod Point {
    use starknet::ContractAddress;
    use starknet::get_tx_info;
    use starknet::get_caller_address;
    use core::pedersen::PedersenTrait;
    use core::hash::{HashStateTrait, HashStateExTrait};
    use openzeppelin::account::interface::{AccountABIDispatcherTrait, AccountABIDispatcher};
    use openzeppelin::security::reentrancyguard::ReentrancyGuardComponent;

    const STARKNET_DOMAIN_TYPE_HASH: felt252 =
        selector!("StarkNetDomain(name:felt,version:felt,chainId:felt)");

    const SIMPLE_STRUCT_TYPE_HASH: felt252 =
        selector!("Ticket(address:ContractAddress,amount:u128,timestamp:u128)");

    component!(path: ReentrancyGuardComponent, storage: reentrancy, event: ReentrancyEvent);

    impl ReentrancyInternalImpl = ReentrancyGuardComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        signer: ContractAddress,
        user: LegacyMap::<ContractAddress, u128>,
        whitelistContract: LegacyMap::<ContractAddress, bool>,
        usedProof: LegacyMap::<felt252, bool>,
        #[substorage(v0)]
        reentrancy: ReentrancyGuardComponent::Storage,
    }
    #[derive(Drop, Copy, Hash)]
    struct Ticket {
        address: ContractAddress,
        amount: u128,
        timestamp: u128,
    }

    #[derive(Drop, Copy, Hash)]
    struct StarknetDomain {
        name: felt252,
        version: felt252,
        chain_id: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, address: ContractAddress) {
        self.owner.write(address);
        self.signer.write(address);
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ReentrancyEvent: ReentrancyGuardComponent::Event,
    }


    #[abi(embed_v0)]
    impl PoolPoint of super::IPoolPoint<ContractState> {
        fn rewardPoint(
            ref self: ContractState, amount: u128, timestamp: u128, proof: Array<felt252>
        ) {
            self.reentrancy.start();
            let address = get_caller_address();
            let msgHash = ValidateSignature::get_message_hash(
                @self, amount, timestamp, self.signer.read()
            );
            assert(self.usedProof.read(msgHash) == false, 'Proof is used');
            assert(
                ValidateSignature::is_valid_signature(
                    @self, self.signer.read(), msgHash, proof
                ) == 'VALID',
                'INVALID SIGNATURE'
            );
            let mut sum = self.user.read(address);
            sum += amount;
            self.usedProof.write(msgHash, true);
            self.user.write(address, sum);
        }

        fn givePoint(ref self: ContractState, addressReceive: ContractAddress, amount: u128) {
            let callerAddress = get_caller_address();
            assert(self.whitelistContract.read(callerAddress) == true, 'Invalid Contract Address');
            let mut sum = self.user.read(addressReceive);
            sum += amount;
            self.user.write(addressReceive, sum);
            self.reentrancy.end();
        }

        fn setPermission(ref self: ContractState, address: ContractAddress, permission: bool) {
            assert(self.owner.read() == get_caller_address(), 'You do not have permission');
            self.whitelistContract.write(address, permission);
        }

        fn get(self: @ContractState, address: ContractAddress) -> u128 {
            self.user.read(address)
        }

        fn getOwner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }
    }


    trait IStructHash<T> {
        fn hash_struct(self: @T) -> felt252;
    }

    impl StructHashStarknetDomain of IStructHash<StarknetDomain> {
        fn hash_struct(self: @StarknetDomain) -> felt252 {
            let mut state = PedersenTrait::new(0);
            state = state.update_with(STARKNET_DOMAIN_TYPE_HASH);
            state = state.update_with(*self);
            state = state.update_with(4);
            state.finalize()
        }
    }

    impl StructHashSimpleStruct of IStructHash<Ticket> {
        fn hash_struct(self: @Ticket) -> felt252 {
            let mut state = PedersenTrait::new(0);
            state = state.update_with(SIMPLE_STRUCT_TYPE_HASH);
            state = state.update_with(*self);
            state = state.update_with(4);
            state.finalize()
        }
    }


    #[generate_trait]
    impl ValidateSignature of IValidateSignature {
        fn is_valid_signature(
            self: @ContractState, signer: ContractAddress, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            let account: AccountABIDispatcher = AccountABIDispatcher { contract_address: signer };
            account.is_valid_signature(hash, signature)
        }

        fn get_message_hash(
            self: @ContractState, amount: u128, timestamp: u128, signer: ContractAddress
        ) -> felt252 {
            let domain = StarknetDomain {
                name: 'poolpoint', version: 1, chain_id: get_tx_info().unbox().chain_id
            };
            let mut state = PedersenTrait::new(0);
            state = state.update_with('StarkNet Message');
            state = state.update_with(domain.hash_struct());
            // This can be a field within the struct, it doesn't have to be get_caller_address().
            state = state.update_with(signer);
            let ticket = Ticket {
                address: get_caller_address(), amount: amount, timestamp: timestamp
            };
            state = state.update_with(ticket.hash_struct());
            // Hashing with the amount of elements being hashed 
            state = state.update_with(4);
            state.finalize()
        }
    }
}

