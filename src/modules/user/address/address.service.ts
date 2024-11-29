import addressModel from './address.model';
import { AddressInputSchema } from '@utils/validator/requestSchemaValidator';
import { AddressSlug } from './address.types';
import { Address } from '@prisma/client';
import { AddressQueryType } from '@utils/types';
import { generateAddressQuery } from '@utils/provider';

export async function updateAddressandReturn(slug: AddressSlug, payload: AddressInputSchema, details: AddressQueryType = ''): Promise<Address> {
    return await addressModel.updateAddress(slug, payload, generateAddressQuery(details));
}

export function updateAddressOptimisticly(slug: AddressSlug, payload: AddressInputSchema): void {
    void addressModel.updateAddress(slug, payload);
}

const AddressServices = { updateAddressandReturn, updateAddressOptimisticly };
export default AddressServices;
