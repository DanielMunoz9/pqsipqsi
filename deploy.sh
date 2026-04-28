#!/bin/bash
# Script de despliegue para Valhala en hosting

echo "🚀 Iniciando despliegue de Valhala..."

# Verificar que existe .env
if [ ! -f .env ]; then
    echo "❌ Error: Archivo .env no encontrado"
    echo "Copia .env.example a .env y configura las variables"
    exit 1
fi

# Verificar variables requeridas
source .env
if [ -z "$SUPABASE_URL" ] || [ -z "$SUPABASE_KEY" ]; then
    echo "❌ Error: SUPABASE_URL y SUPABASE_KEY son requeridos"
    exit 1
fi

echo "✅ Configuración validada"
echo "🌐 URLs de API configuradas automáticamente"
echo "📊 Panel admin: [tu-dominio]/bl-sentinel-9f3a2c"
echo "🔑 Credenciales: admin / PAXn10HCs9edZoVm"
echo ""
echo "🎯 El sistema está listo para hosting!"
echo "Sube este código a GitHub y conéctalo a Railway/Render"