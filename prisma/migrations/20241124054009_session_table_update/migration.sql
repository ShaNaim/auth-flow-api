-- AlterTable
ALTER TABLE "Session" ALTER COLUMN "accessTokenValidityTime" DROP NOT NULL,
ALTER COLUMN "refreshTokenValidityTime" DROP NOT NULL;
