<?php

namespace App\Http\Controllers\API;

use App\Models\Transaction;
use Illuminate\Http\Request;
use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\TransactionItem;
use Illuminate\Support\Facades\Auth;


class TransactionController extends Controller
{
    public function all(Request $request){
        $id = $request->input('id');
        $limit = $request->input('limit', 6);
        $status = $request->input('status');

        if($id){
            $transactions = Transaction::with(['items.product'])->find($id);

            if($transactions){
                return ResponseFormatter::success(
                    $transactions,
                    'Data Transaction Berhasil Diambil'
                );
            }else{
                return ResponseFormatter::error(
                    null,
                    'Data Transaction Tidak Ada',
                    404
                );
            }
        }

        $userId = Auth::id(); // Menggunakan Auth::id() untuk menghindari error jika tidak login

        if (!$userId) {
            return ResponseFormatter::error(
                null,
                'Pengguna belum login',
                401
            );
        }
        $transactions = Transaction::with(['items.product'])->where('users_id', $userId);

        if($status){
            $transactions->where('status', $status);
        }
        return ResponseFormatter::success(
            $transactions->paginate($limit),
            'Data List Transaction Berhasil Diambil'
        );
    }

    public function checkout(Request $request){
         $request->validate([
            'items' => 'required|array',
            'items.*.id' => 'exists:products,id',
            'total_price' => 'required',
            'shipping_price' => 'required',
            'status' => 'required|in:PENDING,SUCCESS,CANCELLED,FAILED,SHIPPING,SHIPPED',
         ]);

         $transactions = Transaction::create([
            'users_id' => Auth::user()->id,
            'address' => $request->address,
            'total_price' => $request->total_price,
            'shipping_price' => $request->shipping_price,
            'status' => $request->status,
         ]);

         foreach($request->items as $product){
            TransactionItem::create([
                'users_id' => Auth::user()->id,
                'products_id' => $product['id'],
                'transactions_id' => $transactions->id,
                'quantity' => $product['quantity'],
            ]);
         }

         return ResponseFormatter::success($transactions->load('items.product'), 'Transaksi Berhasil');
          
    }
}
