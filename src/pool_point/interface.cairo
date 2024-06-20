use starknet::ContractAddress;

const STARKNET_DOMAIN_TYPE_HASH: felt252 =
    selector!("StarkNetDomain(name:felt,version:felt,chainId:felt)");

const SIMPLE_STRUCT_TYPE_HASH: felt252 =
    selector!("SimpleStruct(some_felt252:felt,some_u128:u128)");

#[derive(Drop, Serde, Hash)]
struct SimpleStruct {
    some_felt252: felt252,
    some_u128: u128,
}

#[derive(Drop, Copy, Hash)]
struct StarknetDomain {
    name: felt252,
    version: felt252,
    chain_id: felt252,
}
#[starknet::interface]
trait IPoolPoint<TContractState> {
    fn set(ref self: TContractState, x: u128);
    fn get(self: @TContractState,address: ContractAddress) -> u128;
}

#[starknet::interface]
trait IStructHash<TContractState> {
    fn hash_struct(self: @TContractState) -> felt252;
}

#[starknet::interface]
trait IOffchainMessageHash<TContractState> {
    fn get_message_hash(self: @TContractState) -> felt252;
}