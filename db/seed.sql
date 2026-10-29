-- Datos de ejemplo de identity-service. Ejecutar despues de schema.sql.
INSERT INTO usuario (id_usuario, nombre, apellido, email, telefono, pais_residencia, fecha_registro, estado, cedula, tipo_documento, estado_kyc, role) VALUES
 ('11111111-1111-1111-1111-111111111111','Ana','Demo','ana.demo@example.com','+573001110001','CO',now(),'verificado','1000000001','cedula','aprobado','cliente'),
 ('22222222-2222-2222-2222-222222222222','Luis','Demo','luis.demo@example.com','+573001110002','CO',now(),'verificado','1000000002','cedula','aprobado','cliente')
ON CONFLICT DO NOTHING;
INSERT INTO documento_identidad (id_documento, id_usuario, tipo_documento, numero_documento, pais_emision, fecha_expiracion) VALUES
 ('d0000000-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','cedula','1000000001','CO','2035-01-01'),
 ('d0000000-0000-0000-0000-000000000002','22222222-2222-2222-2222-222222222222','cedula','1000000002','CO','2035-01-01')
ON CONFLICT DO NOTHING;
INSERT INTO verificacion_kyc (id_verificacion, id_usuario, proveedor_externo, resultado, fecha_verificacion) VALUES
 ('e0000000-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','verifik','aprobado',now()),
 ('e0000000-0000-0000-0000-000000000002','22222222-2222-2222-2222-222222222222','verifik','aprobado',now())
ON CONFLICT DO NOTHING;
INSERT INTO evaluacion_riesgo (id_evaluacion, id_verificacion, nivel_riesgo, score, fecha_evaluacion) VALUES
 ('f0000000-0000-0000-0000-000000000001','e0000000-0000-0000-0000-000000000001','bajo',12.50,now()),
 ('f0000000-0000-0000-0000-000000000002','e0000000-0000-0000-0000-000000000002','bajo',15.00,now())
ON CONFLICT DO NOTHING;
