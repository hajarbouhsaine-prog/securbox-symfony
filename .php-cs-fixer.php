<?php

// .php-cs-fixer.php — PHP CS Fixer configuration for SecurBox
// Place this file at the root of your project.

$finder = PhpCsFixer\Finder::create()
    ->in([
        __DIR__ . '/src',
        __DIR__ . '/tests',
    ])
    ->name('*.php')
    ->notPath('var/')
    ->notPath('vendor/')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);

return (new PhpCsFixer\Config())
    ->setRules([
        '@Symfony'               => true,   // Symfony coding standard
        '@PSR12'                 => true,   // PSR-12 standard
        'array_syntax'           => ['syntax' => 'short'],    // [] instead of array()
        'ordered_imports'        => ['sort_algorithm' => 'alpha'],
        'no_unused_imports'      => true,
        'not_operator_with_successor_space' => true,
        'trailing_comma_in_multiline' => true,
        'phpdoc_order'           => true,
        'void_return'            => true,
        'declare_strict_types'   => true,   // enforce strict_types=1
        'concat_space'           => ['spacing' => 'one'],
    ])
    ->setFinder($finder)
    ->setRiskyAllowed(true)   // needed for declare_strict_types + void_return
    ->setCacheFile(__DIR__ . '/var/.php-cs-fixer.cache');
