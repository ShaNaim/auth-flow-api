/*
  Warnings:

  - You are about to drop the column `accessToken` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `accessTokenValidityTime` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `refreshToken` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `refreshTokenValidityTime` on the `Session` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "Session" DROP COLUMN "accessToken",
DROP COLUMN "accessTokenValidityTime",
DROP COLUMN "refreshToken",
DROP COLUMN "refreshTokenValidityTime";
