export default [
  {
    files: ["assets/**/*.js"],
    languageOptions: {
      globals: {
        window: "readonly",
        document: "readonly",
        console: "readonly"
      }
    }
  }
];
