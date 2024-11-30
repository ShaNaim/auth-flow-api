import { PersonInputSchema } from '@utils/validator/requestSchemaValidator';
import { generatePersonQuery } from '@utils/provider';
import { Person } from '@prisma/client';
import { updatePersonModel } from './person.model';
import { PersonSlug, PersonQueryType } from './person.types';

export async function updatePersonandReturn(id: PersonSlug, payload: PersonInputSchema, details: PersonQueryType = ''): Promise<Person> {
    return await updatePersonModel(id, payload, generatePersonQuery(details));
}

export function updatePersonOptimisticly(id: PersonSlug, payload: PersonInputSchema): void {
    void updatePersonModel(id, payload);
}

const personServices = { updatePersonandReturn, updatePersonOptimisticly };
export default personServices;
