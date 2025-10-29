import * as React from "react";
import { Dialog } from "radix-ui";
import { AlertCircle } from "lucide-react";
import type { Dispatch, SetStateAction } from "react";
import { Button } from "@/components/ui/Button";
import { useState } from "react";

interface CheckDuplicateDialogProps {
	msg: string | null;
	setMsg: Dispatch<SetStateAction<string | null>>;
	handleAddCredential: () => Promise<void>;
}

export function CheckDuplicateDialog({ msg, setMsg, handleAddCredential }: CheckDuplicateDialogProps) {
	return (
		<Dialog.Root open={!!msg} onOpenChange={() => setMsg(null)}>
			<Dialog.Portal>
				<Dialog.Overlay className="fixed inset-0 bg-black/50 data-[state=open]:animate-overlayShow" />
				<Dialog.Content className="fixed left-1/2 top-1/2 max-h-[85vh] w-[90vw] max-w-[450px] -translate-x-1/2 -translate-y-1/2 rounded-2xl bg-white dark:bg-gray-800 p-6 shadow-2xl focus:outline-none data-[state=open]:animate-contentShow border border-gray-200 dark:border-gray-700">
						<Dialog.Title className="flex items-center space-x-2 text-xl font-bold text-gray-900 dark:text-white mb-4">
							<AlertCircle className="w-5 h-5 text-amber-600 dark:text-amber-400" />
							<span>Duplicate Credentials Found</span>
						</Dialog.Title>
					<Dialog.Description className="text-gray-600 dark:text-gray-400">
						{msg}
					</Dialog.Description>
					<div className="flex flex-col sm:flex-row gap-3 mt-4">
						<Dialog.Close asChild>
							<Button variant="secondary" className="flex-1">
								Go Back
							</Button>
						</Dialog.Close>
						<Dialog.Close asChild>
							<Button variant="danger" className="flex-1" onClick={handleAddCredential}>
								Proceed Anyway
							</Button>
						</Dialog.Close>
					</div>
				</Dialog.Content>
			</Dialog.Portal>
		</Dialog.Root>
	);
}