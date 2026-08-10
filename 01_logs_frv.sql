-- Tabla de trazabilidad para consulta_frv (mismo patrón que logs_acceso_vi)
create table if not exists public.logs_acceso_frv (
  id bigint generated always as identity primary key,
  usuario_email text,
  accion text,
  detalle text,
  ip_address text,
  creado_en timestamptz not null default now()
);

alter table public.logs_acceso_frv enable row level security;
-- Sin políticas: solo el backend con service_role puede escribir/leer, evitando el bypass de RLS desde el navegador.
