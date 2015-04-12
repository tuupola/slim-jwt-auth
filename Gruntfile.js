module.exports = function(grunt) {
    "use strict";

    grunt.initConfig({
        pkg: grunt.file.readJSON("package.json"),
        watch: {
            php: {
                files: ["src/**/*.php", "tests/**/*.php"],
                tasks: ["testphp"]
            }
        },
        phpunit: {
            unit: {
                dir: "tests"
            },
            options: {
                bin: "vendor/bin/phpunit --coverage-text --coverage-html ./report",
                colors: true,
                testdox: false
            }
        },
        phplint: {
            options: {
                swapPath: "/tmp"
            },
            all: ["src/**/*.php", "tests/**/*.php"]
        },
        phpcs: {
            application: {
                src: ["src/**/*.php", "tests/**/*.php"]
            },
            options: {
                bin: "vendor/bin/phpcs",
                standard: "PSR2"
            }
        }
    });

    require("load-grunt-tasks")(grunt);

    grunt.registerTask("testphp", ["phplint", "phpcs", "phpunit"]);
    grunt.registerTask("default", ["testphp"]);
};