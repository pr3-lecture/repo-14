## Übungsblatt 1

Daniel Meng, 1427948, repo-14<br />
Julian Braasch, 1512359, repo-15<br />
Mustafa Yildiz, 1411880, repo-16<br />

### Aufgabe 1
a) Elemente tauschen

```xml
(defun rotiere (l)
  (append (cdr l) (list (car l)))
)
```

b) Element einfügen

```xml
(defun neues-vorletztes (e l)
  (append (reverse (cdr (reverse l))) (list e) (list (car (reverse l))))
)
```

c) Länge einer Liste berechnen

```xml
(defun my-length (l)
  (do (
      (anz 0 (+ anz 1))
      (listneu l (cdr listneu)))
      ((null listneu) anz)
  )
)
```

d) Länge einer geschachtelten Liste berechnen

```xml
(defun my-lengthR (l)
  (cond ((null l) 0)
        ((listp (car l)) (+ (my-lengthR (car l)) (my-lengthR (cdr l))))
        (T (+ 1 (my-lengthR (cdr l))))
  )
)
```

e) Listen umkehren

```xml
(defun my-reverse (l) 
  (cond (
        (null l) '())	
        (T (append (my-reverse (cdr l)) (list (car l))))
  )
)
```

f) Geschachtelte Listen umkehren

```xml
(defun my-reverseR (l)
  (cond ((null l) nil)
        ((listp (car l)) (append (my-reverseR (cdr l)) (list (my-reverseR (car l)))))
        (T (append (my-reverseR (cdr l)) (list (car l))))
  )
)

```

### Aufgabe 2
a) Darstellung eines Binärbaums

```xml
(8 (4 ((2) (3)))
   (6 ((5) (9)))
)
```
entspricht

```xml
      8
    /   \
  4       6
 / \    /  \
2   3   5   9
```


b) Baumtraversierung

Um die Traversierung zu realisieren, werden zusätzliche Hilfsmethoden "left-tree" und "right-tree" benötigt, welche jeweils den linken bzw. rechten Teilbaum ausgeben.

* Inorder: Erst der linke Teilbaum, dann der Knoten, dann der rechte Teilbaum

```xml
Pseudocode:
(defun inorder (tree)
  (inorder (left-tree tree))
  (print tree)
  (inorder (right-tree tree))
)
```

* Preorder: Erst der Knoten, dann der linke Teilbaum, dann der echte Teilbaum

```xml
(defun preorder (tree)
  (print tree)
  (preorder (left-tree tree))
  (preorder (right-tree tree))
)
```

* Postorder: Erst der linke Teilbaum, dann der rechte Teilbaum, dann den Knoten

```xml
(defun postorder (tree)
  (postorder (left-tree tree))
  (postorder (right-tree tree)
  (print tree)
)
```
