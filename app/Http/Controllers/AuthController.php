<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    // register new user
    public function register(Request $request)
    {
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed',
        ]);

        // create user
        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password']),
        ]);

        // create token
        $token = $user->createToken('myapptoken')->plainTextToken;

        // response
        $response = [
            'user' => $user,
            'token' => $token,
        ];

        return response($response, 201);
    }



    // user login
    public function login(Request $request)
    {
        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
        ]);

        // check email
        $user = User::where('email', $fields['email'])->first();

        // Check password
        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response()->json(['message' => 'Bad Credentials'], 401);
        }

        // create token
        $token = $user->createToken('myapptoken')->plainTextToken;

        // response
        $response = [
            'user' => $user,
            'token' => $token,
        ];

        return response()->json([$response], 201);
    }


    // logout user and destroy access token
    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();
        // auth()->user()->logout;
        
        return response()->json(['message' => 'Logged out']);
    }
}
