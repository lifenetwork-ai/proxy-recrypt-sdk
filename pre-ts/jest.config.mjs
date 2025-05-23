/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
    preset: "ts-jest",
    testEnvironment: "jsdom",
    testEnvironmentOptions: {
        customExportConditions: ["react-native"],
    },
    extensionsToTreatAsEsm: [".ts", ".tsx"],
    moduleNameMapper: {
        "^(\\.{1,2}/.*)\\.js$": "$1",
        "^(\\.{1,2}/.*)\\.ts$": "$1",
    },
    transform: {
        "^.+\\.tsx?$": [
            "ts-jest",
            {
                tsconfig: "tsconfig.json",
                useESM: true,
            },
        ],
    },
    transformIgnorePatterns: [],
    collectCoverage: true,
    coverageReporters: ["text", "cobertura"],
    coveragePathIgnorePatterns: [
        "/node_modules/",
        "/dist/",
        "/mocks/",
        "index.ts",
        "types.ts",
    ],
};
