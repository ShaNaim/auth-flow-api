/* eslint-disable @typescript-eslint/typedef */
export class ErrorCodes {
    public static readonly Unauthenticated = 'Unauthenticated';
    public static readonly Unauthorized = 'Unauthorized';
    public static readonly NotFound = 'NotFound';
    public static readonly ValidationError = 'ValidationError';
    public static readonly EmailExists = 'EmailExists';
    public static readonly UsernameExists = 'UsernameExists';
    public static readonly ItemExists = 'ItemExists';
    public static readonly AuthError = 'AuthError';
    public static readonly VerificationError = 'VerificationError';
    public static readonly JwtError = 'JwtError';
    public static readonly AsyncError = 'AsyncError';
    public static readonly UnknownError = 'UnknownError';
    public static readonly InvalidID = 'InvalidID';
    public static readonly CrudError = 'CrudError';
    public static readonly ServerBusy = 'ServerBusy';
    public static readonly CorsError = 'CorsError';
}
