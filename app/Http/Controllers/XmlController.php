<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class XmlController extends Controller
{
    public function firmarXml(Request $request)
    {   
        // Validar los parámetros recibidos
        $validatedData = $request->validate([
            'xml' => 'required|string', // El XML debe ser una cadena de texto
            'firma' => 'required|string', // La firma codificada en Base64
            'password' => 'required|string', // La contraseña
        ]);
        // Obtener los parámetros
        $xmlSinFirmar = $validatedData['xml'];
        $firma = $validatedData['firma'];
        $password = $validatedData['password'];
        $rutaArchivo = base_path('app/Http/Scripts/Firmador.php');
        include($rutaArchivo);
        return $xmlFirmado->xml;
    }
}