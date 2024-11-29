import { UserQueryTypes, PersonQueryType, personQueryTypes, AddressQueryType, addressQueryOptions, UserQueryOptions } from '@utils/types';

const address = (value: boolean) => ({
    select: {
        slug: true,
        street: value,
        city: value,
        postalCode: value,
        country: value,
        district: value,
        area: value
    }
});

const person = (value: boolean) => ({ firstName: value, lastName: value, phone: value, slug: true });

function addressQuery(includeAddress: boolean) {
    if (includeAddress) return address(true);
    return address(false);
}

function personQuery(includePerson: boolean, includeAddress: boolean) {
    if (includePerson)
        return {
            select: {
                ...person(true),
                address: addressQuery(includeAddress)
            }
        };
    return {
        select: {
            ...person(false),
            address: addressQuery(includeAddress)
        }
    };
}

const userQuery = (options: UserQueryOptions) => ({
    select: {
        email: true,
        password: false,
        slug: true,
        person: personQuery(options.includePerson, options.includeAddress)
    }
});

export function generateUserQuery(details: UserQueryTypes = null) {
    const options: UserQueryOptions = { includePerson: false, includeAddress: false };

    if (details) {
        options.includePerson = true;
        options.includeAddress = true;
    }
    return userQuery(options);
}

export function generatePersonQuery(details: PersonQueryType) {
    const options: UserQueryOptions = { includePerson: false, includeAddress: false };

    if (details === personQueryTypes.all) {
        options.includePerson = true;
        options.includeAddress = true;
    }
    if (details === personQueryTypes.person) {
        options.includePerson = true;
        options.includeAddress = false;
    }
    if (details === personQueryTypes.address) {
        options.includePerson = false;
        options.includeAddress = true;
    }
    return personQuery(options.includePerson, options.includeAddress);
}

export function generateAddressQuery(details: AddressQueryType) {
    if (details === addressQueryOptions) return addressQuery(true);
    return addressQuery(false);
}
