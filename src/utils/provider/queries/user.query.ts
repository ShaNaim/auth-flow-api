import { UserQueryTypes } from '@utils/types';
type UserQueryOptions = { includePerson: boolean; includeAddress: boolean };

const options: UserQueryOptions = { includePerson: false, includeAddress: false };
const address = {
    select: {
        slug: true,
        street: true,
        city: true,
        postalCode: true,
        country: true,
        district: true,
        area: true
    }
};

function addressQuery(includeAddress: boolean) {
    if (includeAddress) return address;
    return false;
}

function personQuery(includePerson: boolean, includeAddress: boolean) {
    if (includePerson)
        return {
            select: {
                firstName: true,
                lastName: true,
                phone: true,
                slug: true,
                address: addressQuery(includeAddress)
            }
        };
    return false;
}

const generateUserQuery = (options: UserQueryOptions) => ({
    select: {
        email: true,
        password: false,
        slug: true,
        person: personQuery(options.includePerson, options.includeAddress)
    }
});

export function userQuery(details: UserQueryTypes = null) {
    if (details) {
        options.includePerson = true;
        options.includeAddress = true;
    }
    return generateUserQuery(options);
}
