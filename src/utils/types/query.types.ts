export const addressQueryOptions = 'address';

export const personQueryTypes = {
    all: 'all',
    person: 'person',
    address: addressQueryOptions
};

export type UserQueryTypes = true | false | null;
export type UserQueryOptions = { includePerson: boolean; includeAddress: boolean };

export type PersonQueryType = (typeof personQueryTypes)[keyof typeof personQueryTypes] | null;

export type AddressQueryType = 'address' | null | '';
