/*
  Warnings:

  - Made the column `slug` on table `Address` required. This step will fail if there are existing NULL values in that column.
  - Made the column `slug` on table `Person` required. This step will fail if there are existing NULL values in that column.
  - Made the column `slug` on table `User` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "Address" ALTER COLUMN "slug" SET NOT NULL;

-- AlterTable
ALTER TABLE "Person" ALTER COLUMN "slug" SET NOT NULL;

-- AlterTable
ALTER TABLE "User" ALTER COLUMN "slug" SET NOT NULL;
