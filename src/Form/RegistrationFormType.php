<?php

declare(strict_types=1);

namespace App\Form;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\IsTrue;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class RegistrationFormType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('email')
            ->add('agreeTerms', CheckboxType::class, [
                'mapped' => false,
                'constraints' => [
                    new IsTrue(message: 'You should agree to our terms.'),
                ],
            ])
            ->add('plainPassword', PasswordType::class, [
                'mapped' => false,
                'attr' => ['autocomplete' => 'new-password'],
                'constraints' => [
                    new NotBlank(message: 'Please enter a password'),
                    new Length(
                        min: 6,
                        minMessage: 'Your password should be at least {{ limit }} characters',
                        max: 4096,
                    ),
                ],
            ])
            ->add('securityQuestion', ChoiceType::class, [
                'mapped' => true,
                'placeholder' => 'Choisissez une question de sécurité',
                'choices' => [
                    'Quel est le nom de votre animal de compagnie ?' => 'Quel est le nom de votre animal de compagnie ?',
                    'Quelle est la ville de votre naissance ?' => 'Quelle est la ville de votre naissance ?',
                    'Quel est le prénom de votre meilleur(e) ami(e) d\'enfance ?' => 'Quel est le prénom de votre meilleur(e) ami(e) d\'enfance ?',
                    'Quel est le nom de votre école primaire ?' => 'Quel est le nom de votre école primaire ?',
                    'Quel est votre plat préféré ?' => 'Quel est votre plat préféré ?',
                    'Quelle est la marque de votre première voiture ?' => 'Quelle est la marque de votre première voiture ?',
                    'Quel est le nom de votre professeur préféré ?' => 'Quel est le nom de votre professeur préféré ?',
                    'Créez une phrase de récupération personnelle que vous seul connaissez.' => 'Créez une phrase de récupération personnelle que vous seul connaissez.',
                ],
                'constraints' => [
                    new NotBlank(message: 'Veuillez choisir une question de sécurité'),
                ],
            ])
            ->add('securityAnswer', TextType::class, [
                'mapped' => false,
                'attr' => [
                    'placeholder' => 'Votre réponse',
                    'autocomplete' => 'off',
                ],
                'constraints' => [
                    new NotBlank(message: 'Veuillez entrer une réponse'),
                    new Length(
                        min: 2,
                        minMessage: 'La réponse doit contenir au moins {{ limit }} caractères',
                        max: 255,
                    ),
                ],
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => User::class,
        ]);
    }
}
