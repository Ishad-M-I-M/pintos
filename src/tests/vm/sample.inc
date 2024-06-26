char sample[] = { "=== ALL USERS PLEASE NOTE ========================\n" "\n"
"CAR and CDR now return extra values.\n" "\n" "The function CAR now returns two
values. Since it has to go to the\n" "trouble to figure out if the object is
carcdr-able anyway, we figured\n" "you might as well get both halves at once.
For example, the following\n" "code shows how to destructure a cons (SOME-CONS)
into its two slots\n" "(THE-CAR and THE-CDR):\n" "\n" " (MULTIPLE-VALUE-BIND
(THE-CAR THE-CDR) (CAR SOME-CONS) ...)\n" "\n" "For symmetry with CAR, CDR
returns a second value which is the CAR of\n" "the object. In a related change,
the functions MAKE-ARRAY and CONS\n" "have been fixed so they don't allocate any
storage except on the\n" "stack. This should hopefully help people who don't
like using the\n" "garbage collector because it cold boots the machine so
often.\n" };
