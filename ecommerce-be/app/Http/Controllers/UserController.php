<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    //register User
    public function register(Request $request)
    {
        $user = User::create([
            'name'=> $request->name,
            'email'=>$request->email,
            'password'=>Hash::make($request->password)
        ]);

        if($user){
            return response()->json(['message'=>'User Registered Successfully','status'=>1, 'user'=>$user]);
        }else{
            return response()->json(['message'=>'something Went Wrong','status'=>0]);
        }
    }

    // Login User
    public function login(Request $request)
    {
        $email = $request->email;
        $password = $request->password;
        
        $user = User::where('email', $email)->first();
        
        if($user) {
            if(Hash::check($password, $user->password)) {
                $token = $user->createToken('auth_token')->plainTextToken;
                return response()->json(['message' => 'Login successful', 'status' => 1, 'token' => $token,'user'=>$user]);
            } else {
                return response()->json(['message' => 'Incorrect password', 'status' => 0]);
            }
        } else {
            return response()->json(['message' => 'User not found', 'status' => 0]);
        }
    }


    public function logout(Request $request)
    {
        // $request->user()->currentAccessToken()->delete();
        $request->session()->invalidate();

        $request->session()->regenerateToken();
        
        return response()->json(['message' => 'Logout successful', 'status' => 1]);
    }

    public function getUserById(Request $request, $userId)
    {
        $user = User::find($userId);

        if ($user) {
            return response()->json(['user' => $user]);
        } else {
            return response()->json(['message' => 'User not found', 'status' => 0], 404);
        }
    }

}
