"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useAuth } from "@/contexts/AuthContext";
import { credentialsAPI, Credential } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card } from "@/components/ui/Card";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import {
  Plus,
  LogOut,
  Eye,
  EyeOff,
  Copy,
  Globe,
  User,
  Lock,
  Search,
  Shield,
  Key,
} from "lucide-react";

function DashboardContent() {
  const { user, logout } = useAuth();
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [visiblePasswords, setVisiblePasswords] = useState<Set<number>>(
    new Set()
  );
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  // Form state
  const [formData, setFormData] = useState({
    site: "",
    account: "",
    site_password: "",
  });
  const [formLoading, setFormLoading] = useState(false);
  const [formError, setFormError] = useState("");

  useEffect(() => {
    loadCredentials();
  }, []);

  const loadCredentials = async () => {
    try {
      setLoading(true);
      const response = await credentialsAPI.getCredentials();
      setCredentials(response.credentials || []);
    } catch (error: any) {
      console.error("Failed to load credentials:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");
    setFormLoading(true);

    try {
      await credentialsAPI.addCredential(
        formData.site,
        formData.account,
        formData.site_password
      );

      setFormData({ site: "", account: "", site_password: "" });
      setShowAddForm(false);
      await loadCredentials();
    } catch (error: any) {
      setFormError(error.response?.data?.error || "Failed to add credential");
    } finally {
      setFormLoading(false);
    }
  };

  const togglePasswordVisibility = (index: number) => {
    const newVisible = new Set(visiblePasswords);
    if (newVisible.has(index)) {
      newVisible.delete(index);
    } else {
      newVisible.add(index);
    }
    setVisiblePasswords(newVisible);
  };

  const copyToClipboard = async (text: string, index: number) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
    } catch (error) {
      console.error("Failed to copy:", error);
    }
  };

  const filteredCredentials = credentials.filter(
    (cred) =>
      cred.site.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cred.account.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
          className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full"
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 bg-blue-100 dark:bg-blue-900 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              </div>
              <h1 className="text-xl font-bold text-gray-900 dark:text-white">
                TACO Password Manager
              </h1>
            </div>

            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600 dark:text-gray-400">
                Welcome, <span className="font-medium">{user}</span>
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={logout}
                className="flex items-center space-x-2"
              >
                <LogOut className="w-4 h-4" />
                <span>Logout</span>
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats and Add Button */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-8 space-y-4 sm:space-y-0">
          <div className="flex items-center space-x-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {credentials.length}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                Stored Passwords
              </div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                <Shield className="w-6 h-6 inline" />
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                Encrypted
              </div>
            </div>
          </div>

          <Button
            onClick={() => setShowAddForm(true)}
            className="flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>Add Password</span>
          </Button>
        </div>

        {/* Search */}
        <div className="mb-6">
          <div className="relative max-w-md">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
            <input
              type="text"
              placeholder="Search passwords..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
            />
          </div>
        </div>

        {/* Add Credential Form */}
        <AnimatePresence>
          {showAddForm && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="mb-8"
            >
              <Card>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                  Add New Credential
                </h2>

                <form onSubmit={handleAddCredential} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Input
                      label="Website/Service"
                      value={formData.site}
                      onChange={(e) =>
                        setFormData({ ...formData, site: e.target.value })
                      }
                      placeholder="e.g., gmail.com"
                      icon={<Globe size={20} />}
                      required
                    />

                    <Input
                      label="Username/Email"
                      value={formData.account}
                      onChange={(e) =>
                        setFormData({ ...formData, account: e.target.value })
                      }
                      placeholder="e.g., user@gmail.com"
                      icon={<User size={20} />}
                      required
                    />
                  </div>

                  <Input
                    label="Password"
                    type="password"
                    value={formData.site_password}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        site_password: e.target.value,
                      })
                    }
                    placeholder="Enter the password"
                    icon={<Lock size={20} />}
                    showPasswordToggle
                    required
                  />

                  {formError && (
                    <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                      <p className="text-sm text-red-600 dark:text-red-400">
                        {formError}
                      </p>
                    </div>
                  )}

                  <div className="flex space-x-3">
                    <Button
                      type="submit"
                      loading={formLoading}
                      className="flex-1"
                    >
                      <Key className="w-4 h-4 mr-2" />
                      Save Credential
                    </Button>
                    <Button
                      type="button"
                      variant="secondary"
                      onClick={() => {
                        setShowAddForm(false);
                        setFormData({
                          site: "",
                          account: "",
                          site_password: "",
                        });
                        setFormError("");
                      }}
                    >
                      Cancel
                    </Button>
                  </div>
                </form>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Credentials List */}
        <div className="space-y-4">
          <AnimatePresence>
            {filteredCredentials.length === 0 ? (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="text-center py-12"
              >
                <Shield className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                  {searchTerm
                    ? "No matching passwords found"
                    : "No passwords stored yet"}
                </h3>
                <p className="text-gray-600 dark:text-gray-400 mb-6">
                  {searchTerm
                    ? "Try adjusting your search terms"
                    : "Add your first password to get started"}
                </p>
                {!searchTerm && (
                  <Button onClick={() => setShowAddForm(true)}>
                    <Plus className="w-4 h-4 mr-2" />
                    Add Your First Password
                  </Button>
                )}
              </motion.div>
            ) : (
              filteredCredentials.map((cred, index) => (
                <motion.div
                  key={`${cred.site}-${cred.account}`}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ delay: index * 0.1 }}
                >
                  <Card hover className="p-6">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900 rounded-lg flex items-center justify-center">
                            <Globe className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                          </div>
                          <div>
                            <h3 className="font-semibold text-gray-900 dark:text-white">
                              {cred.site}
                            </h3>
                            <p className="text-sm text-gray-600 dark:text-gray-400">
                              {cred.account}
                            </p>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2">
                        <div className="flex items-center space-x-2 bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2">
                          <input
                            type={
                              visiblePasswords.has(index) ? "text" : "password"
                            }
                            value={cred.site_password}
                            readOnly
                            className="bg-transparent text-sm font-mono min-w-0 flex-1 outline-none"
                          />
                          <button
                            onClick={() => togglePasswordVisibility(index)}
                            className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                          >
                            {visiblePasswords.has(index) ? (
                              <EyeOff size={16} />
                            ) : (
                              <Eye size={16} />
                            )}
                          </button>
                          <button
                            onClick={() =>
                              copyToClipboard(cred.site_password, index)
                            }
                            className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                          >
                            {copiedIndex === index ? (
                              <span className="text-green-600 text-xs">
                                Copied!
                              </span>
                            ) : (
                              <Copy size={16} />
                            )}
                          </button>
                        </div>
                      </div>
                    </div>
                  </Card>
                </motion.div>
              ))
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <ProtectedRoute>
      <DashboardContent />
    </ProtectedRoute>
  );
}
