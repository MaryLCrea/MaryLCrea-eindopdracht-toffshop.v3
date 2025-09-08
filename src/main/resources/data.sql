--Users
INSERT INTO users (name, email, password)
VALUES
('Piet Puk', 'piet@email.com', '$2a$14$xA9v7sQGqiniWdh0AE0qQ.BlERiBbk60FaJRWdFg3wBWLgKH.pIK2'),
('Tessa Pluk', 'tessa@email.com', '$2a$14$vwtLcU.9HivcnD8Ne7SHMeGaXP.SVDJCujqRe4.KCtXTHpfuSVE6q');


--Roles
INSERT INTO roles(rolename)
VALUES ('ROLE_USER'), ('ROLE_ADMIN');

-- User-Roles
INSERT INTO user_roles (user_id, role_name)
VALUES
(1,  'ROLE_USER'),
(2,  'ROLE_ADMIN');


--Products
INSERT INTO products (name, description, price, category, brand, color, heel, size, stock_quantity, is_active, created_at, updated_at)
VALUES
('PortDance PD025 Latin', 'Professional Latin dance shoes with suede sole and ankle strap', 129.99, 'FASHION', 'PORTDANCE', 'BLACK', 'HIGH', 'SIZE_38', 15, true, '2025-01-10 10:00:00', '2025-01-15 14:30:00'),
('Ray Rose 825 Ballroom', 'Elegant ballroom shoes for standard dancing with leather sole', 149.99, 'FASHION', 'RAYROSE', 'NUDE', 'MEDIUM', 'SIZE_39', 12, true, '2025-01-11 09:15:00', '2025-01-14 16:45:00'),

-- Health products
('Yoga Mat Premium', 'High-quality yoga mat with excellent grip and cushioning', 45.99, 'HEALTH', NULL, NULL, NULL, NULL, 30, false, '2025-01-08 12:00:00', '2025-01-15 09:30:00'),
('Protein Powder Vanilla', 'Whey protein powder for muscle building and recovery', 29.99, 'HEALTH', NULL, NULL, NULL, NULL, 50, true, '2025-01-09 15:30:00', '2025-01-14 11:20:00'),

-- Kitchen products
('Chef Knife Set', 'Professional chef knife set with wooden block and sharpener', 89.99, 'KITCHEN', NULL, NULL, NULL, NULL, 15, false, '2025-01-10 16:45:00', '2025-01-16 13:40:00'),
('Coffee Machine Deluxe', 'Automatic coffee machine with milk frother and timer', 299.99, 'KITCHEN', NULL, NULL, NULL, NULL, 8, true, '2025-01-11 10:20:00', '2025-01-15 16:50:00'),

-- Tools products
('Drill Set Professional', 'Complete drill set with various bits and carrying case', 79.99, 'TOOLS', NULL, NULL, NULL, NULL, 12, true, '2025-01-12 13:15:00', '2025-01-17 08:25:00');

-- Carts
INSERT INTO carts (user_id, created_at, updated_at)
VALUES
(1, '2025-01-15 10:00:00', '2025-01-15 14:30:00'),
(2, '2025-01-14 09:15:00', '2025-01-14 16:45:00');

-- Order_Items winkelwagenPD025
INSERT INTO order_items  (cart_id, order_id, product_name, product_price, quantity, status)
VALUES
(1, NULL, 'PortDance PD025 Latin', 129.99, 1, 'INCART'),
(1, NULL, 'Yoga Mat Premium', 45.99, 1, 'CANCELLED');

-- Order_Items winkelwagen 2
INSERT INTO order_items (cart_id, order_id, product_name, product_price, quantity, status)
VALUES
(2, 1001, 'Ray Rose 825 Ballroom', 149.99, 1, 'ORDERED'),
(2, 1001, 'Coffee Machine Deluxe', 299.99, 1, 'SHIPPED');

-- Contacts
INSERT INTO contacts (name, email, subject, message, created_at, is_read)
VALUES
('Emma de Vries', 'emma@email.nl', 'Vraag over dansschoenen', 'Hallo, ik zou graag willen weten welke maat ik moet bestellen voor de PortDance schoenen. Ik heb normaal maat 38.', '2025-01-20 14:30:00', false),
('Tom Janssen', 'tom@email.nl', 'Retour aanvraag', 'De Ray Rose schoenen die ik heb besteld zijn te klein. Kan ik deze retourneren voor een grotere maat?', '2025-01-19 16:45:00', true);