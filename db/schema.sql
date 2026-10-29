-- Esquema de identity-service (PostgreSQL). Generado a partir de los modelos SQLAlchemy.
-- Tambien se crea solo al arrancar el servicio (Base.metadata.create_all).

CREATE TABLE usuario (
	id_usuario UUID NOT NULL, 
	nombre VARCHAR(120) NOT NULL, 
	apellido VARCHAR(120), 
	email VARCHAR(255) NOT NULL, 
	telefono VARCHAR(32), 
	pais_residencia VARCHAR(2) NOT NULL, 
	fecha_registro TIMESTAMP WITH TIME ZONE NOT NULL, 
	estado VARCHAR(32) NOT NULL, 
	password_hash VARCHAR(255), 
	fecha_nacimiento VARCHAR(20), 
	servicio_solicitado VARCHAR(100), 
	cedula VARCHAR(50), 
	fecha_expedicion VARCHAR(20), 
	fecha_vencimiento VARCHAR(20), 
	pais_expedicion VARCHAR(10), 
	estado_kyc VARCHAR(40), 
	tipo_documento VARCHAR(30), 
	representante_nombre VARCHAR(120), 
	representante_documento VARCHAR(50), 
	representante_tipo_documento VARCHAR(30), 
	representante_parentesco VARCHAR(30), 
	representante_telefono VARCHAR(32), 
	representante_email VARCHAR(120), 
	role VARCHAR(20) NOT NULL, 
	reset_code VARCHAR(10), 
	reset_code_expires TIMESTAMP WITHOUT TIME ZONE, 
	pin_hash VARCHAR(255), 
	clave_dinamica_codigo VARCHAR(6), 
	clave_dinamica_expira TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id_usuario), 
	UNIQUE (email)
);
CREATE INDEX idx_usuario_email ON usuario (email);

CREATE TABLE documento_identidad (
	id_documento UUID NOT NULL, 
	id_usuario UUID NOT NULL, 
	tipo_documento VARCHAR(32) NOT NULL, 
	numero_documento VARCHAR(32) NOT NULL, 
	pais_emision VARCHAR(2), 
	fecha_expiracion DATE NOT NULL, 
	PRIMARY KEY (id_documento), 
	CONSTRAINT ck_documento_tipo CHECK (tipo_documento IN ('cedula','tarjeta_identidad','cedula_extranjeria','pasaporte','licencia')), 
	FOREIGN KEY(id_usuario) REFERENCES usuario (id_usuario) ON DELETE CASCADE, 
	UNIQUE (numero_documento)
);
CREATE INDEX idx_documento_usuario ON documento_identidad (id_usuario);

CREATE TABLE verificacion_kyc (
	id_verificacion UUID NOT NULL, 
	id_usuario UUID NOT NULL, 
	proveedor_externo VARCHAR(64) NOT NULL, 
	resultado VARCHAR(32) NOT NULL, 
	fecha_verificacion TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id_verificacion), 
	CONSTRAINT ck_verificacion_resultado CHECK (resultado IN ('pendiente','aprobado','rechazado')), 
	FOREIGN KEY(id_usuario) REFERENCES usuario (id_usuario) ON DELETE CASCADE
);
CREATE INDEX idx_verificacion_usuario ON verificacion_kyc (id_usuario);

CREATE TABLE evaluacion_riesgo (
	id_evaluacion UUID NOT NULL, 
	id_verificacion UUID NOT NULL, 
	nivel_riesgo VARCHAR(16) NOT NULL, 
	score NUMERIC(5, 2) NOT NULL, 
	fecha_evaluacion TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id_evaluacion), 
	CONSTRAINT ck_evaluacion_nivel CHECK (nivel_riesgo IN ('bajo','medio','alto')), 
	FOREIGN KEY(id_verificacion) REFERENCES verificacion_kyc (id_verificacion) ON DELETE CASCADE
);
CREATE INDEX idx_evaluacion_verificacion ON evaluacion_riesgo (id_verificacion);
