# Shopmate API

The `shopmate-api` is a TypeScript-based Express application designed for building an e-commerce platform. It uses modern JavaScript and TypeScript

features, with development tools for linting, formatting, and maintaining code quality.

### Prerequisites

-   **Node.js**: `v20.16.0`

-   **npm**: `>=10.8.2`

-   Ensure that Node.js and npm versions match the requirements specified in the `engines` section. Use tools like `nvm` (Node Version Manager) for

managing Node.js versions.

### Installation

1.  **Clone the repository**:

```bash
git  clone  https://github.com/ShaNaim/shopmate.git
```

```bash
cd  shopmate
```

2.  **Install dependencies**: Make sure to install both the development and production dependencies:

```bash
npm  install
```

3.  **Environment Setup**:

-   Create a `.env` file in the root of your project with the necessary environment variables. Refer to `.env.example` if available.

-   Use the `envalid` package to ensure that your environment variables are properly validated.

4. **Database Setup**:

    - **Install PostgreSQL**: If PostgreSQL is not installed on your machine, follow the instructions for your operating system:
        - On macOS:
            ```bash
            brew install postgresql
            ```
        - On Ubuntu:
            ```bash
            sudo apt update
            ```
            ```bash
            sudo apt install postgresql postgresql-contrib
            ```
    - **Configure PostgreSQL**: After installation, start PostgreSQL and create a new database:

        ```bash
        # Start PostgreSQL service
        sudo service postgresql start
        ```

        ```bash
        # Open PostgreSQL prompt
        sudo -u postgres psql
        ```

        ```sql
        # Create a new database for ShopMate
        CREATE DATABASE shopmate;
        ```

    - **Configure Prisma**:
        - **Set `DATABASE_URL` in the `.env` file**: Replace the `DATABASE_URL` in your `.env` with the connection URL for PostgreSQL. For example:
          `env DATABASE_URL="postgresql://user:password@localhost:5432/shopmate" `
        - **Run Prisma Migrations**: After configuring the database, run Prisma migrations to create the necessary tables:
            ```bash
            npx prisma migrate dev --name init
            ```
            This will apply the initial database schema based on your `schema.prisma`.

5. **Build the project**: Compile the TypeScript files into JavaScript:
    ```bash
    npm  run  build
    ```
6. **Start the server**: After building the project, start the server using:

    ```bash
    npm  start
    ```

7. **Run in Development Mode**: To run the server in development mode with automatic reloads using `nodemon` and `ts-node`, use:

    ```bash
    npm  run  dev
    ```

### Usage

-   **Development Server**: Running `npm run dev` will start the server with hot reloading, making it easier for development.

-   **Production Build**: To create a production build, use `npm run build` and then `npm start` to run the compiled JavaScript files.

-   **Linting**: Check code quality using ESLint:

    ```bash
    npm  run  lint
    ```

-   **Code Formatting**: Format the codebase with Prettier:

    ```bash
    npm  run  format
    ```

-   **Clean Build Artifacts**: To remove the `dist` directory (where the compiled JavaScript files are stored):

    ```bash
    npm  run  clean
    ```

### Project Structure

-   `src/`: Main source folder containing the TypeScript files.

-   `dist/`: Compiled JavaScript files are output here after running `npm run build`.

-   `@config`, `@middlewares`, `@modules`, `@utils`, etc.: These are module aliases to simplify imports in your TypeScript code.

### Contributing

We welcome contributions! To contribute, follow these steps:

1.  **Fork the repository**: Click the "Fork" button at the top of the [GitHub repository](https://github.com/ShaNaim/shopmate).

2.  **Clone your fork**:

    ```bash
    git  clone  https://github.com/your-username/shopmate.git
    ```

    ```bash
    cd  shopmate
    ```

3.  **Create a new branch**: Make sure to give your branch a descriptive name:

    ```bash
    git  checkout  -b  feature/your-feature-name
    ```

4.  **Make your changes**.

5.  **Run tests and lint**: Make sure your code passes linting and any tests before submitting a pull request:

    ```bash
    npm  run  lint
    ```

    ```bash
    npm  test
    ```

6.  **Commit and push your changes**:

    ```bash
    git  add  .
    ```

    ```bash
    git  commit  -m  "Add a description of your changes"
    ```

    ```bash
    git  push  origin  feature/your-feature-name
    ```

7.  **Create a pull request**: Go to your forked repository on GitHub, and click the "New pull request" button.

### Additional Information

-   **Lint-Staged**: This project uses `lint-staged` to automatically run `eslint` and `prettier` on staged files before committing, ensuring
    consistent code quality.

-   **Module Aliases**: Use the aliases defined in `_moduleAliases` to simplify imports. For example:

```ts
import { someUtil } from '@utils/someUtil';
```

### Troubleshooting

-   If you encounter issues with the Node version, ensure that you are using `v20.16.0`. Use `nvm` to manage Node versions:

```bash
nvm  install  20.16.0
```

```bash
nvm  use  20.16.0
```

-   Make sure that `.env` is properly configured with the required environment variables, as missing variables can cause the server to fail on
    startup.

---

This guide covers the essential steps to get started with `shopmate-api`, as well as details on contributing and maintaining code quality. Happy

coding!
