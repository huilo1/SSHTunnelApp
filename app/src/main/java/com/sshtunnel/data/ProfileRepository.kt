package com.sshtunnel.data

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

class ProfileRepository(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("ssh_profiles", Context.MODE_PRIVATE)
    private val gson = Gson()

    fun getAll(): List<ServerProfile> {
        val json = prefs.getString("profiles", null) ?: return emptyList()
        val type = object : TypeToken<List<ServerProfile>>() {}.type
        return gson.fromJson(json, type)
    }

    fun save(profile: ServerProfile) {
        val list = getAll().toMutableList()
        val idx = list.indexOfFirst { it.id == profile.id }
        if (idx >= 0) list[idx] = profile else list.add(profile)
        persist(list)
    }

    fun delete(id: String) {
        persist(getAll().filter { it.id != id })
    }

    fun getSelectedId(): String? = prefs.getString("selected_id", null)

    fun setSelectedId(id: String?) {
        prefs.edit().putString("selected_id", id).apply()
    }

    private fun persist(list: List<ServerProfile>) {
        prefs.edit().putString("profiles", gson.toJson(list)).apply()
    }
}
